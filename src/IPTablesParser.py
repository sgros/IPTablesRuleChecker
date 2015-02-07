#!/usr/bin/python
# -*- coding: utf-8 -*-

# Script to check validity of firewall rules
# Copyright (C) 2015 Stjepan Groš
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys
import re
import ipaddr
import shlex
import traceback
import ConfigParser
from collections import OrderedDict

class ContradictingParameters(Exception): pass
class ForbiddedCommand(Exception): pass
class UnexpectedCondition(Exception): pass
class ParsingException(Exception): pass
class UnknownTable(Exception): pass

class Match(object):

	def __init__(self, elements):

		self.name = elements['name']
		del elements['name']

class MatchTCP(Match):

	idx = "TCP"

	def __str__(self):
		retVal = "-m tcp"

		if self.sport is not None:
			retVal = "{} --sport {}".format(retVal, self.sport)

		if self.dport is not None:
			retVal = "{} --dport {}".format(retVal, self.dport)

		return retVal

	def __gt__(self, match):
		"""
		Compute if

			self > match

		meaning if self is a more general version than match. If it
		is, return True, otherwise, return False.
		"""

		if self.sport is not None and match.sport is None:
			return False

		if self.dport is not None and match.dport is None:
			return False

		return self.sport == match.sport and self.dport == match.dport

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		return self.sport == match.sport and self.dport == match.dport

	def __ne__(self, match):
		return self.sport != match.sport or self.dport != match.dport

	def __init__(self, elements):

		super(MatchTCP, self).__init__(elements)

		self.breadth = 100

		if elements.has_key('--sport'):
			self.sport = elements['--sport']
			del elements['--sport']
			self.breadth += 1000
		else:
			self.sport = None

		if elements.has_key('--dport'):
			self.dport = elements['--dport']
			del elements['--dport']
			self.breadth += 1000
		else:
			self.dport = None

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name, self.sport, self.dport]

class MatchUDP(Match):

	idx = "UDP"

	def __str__(self):
		retVal = "-m udp"

		if self.sport is not None:
			retVal = "{} --sport {}".format(retVal, self.sport)

		if self.dport is not None:
			retVal = "{} --dport {}".format(retVal, self.dport)

		return retVal

	def __gt__(self, match):
		"""
		Compute if

			self > match

		meaning if self is a more general version than match. If it
		is, return True, otherwise, return False.
		"""

		if self.sport is not None and match.sport is None:
			return False

		if self.dport is not None and match.dport is None:
			return False

		return self.sport == match.sport and self.dport == match.dport

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		return self.sport == match.sport and self.dport == match.dport

	def __ne__(self, match):
		return self.sport != match.sport or self.dport != match.dport

	def __init__(self, elements):

		super(MatchUDP, self).__init__(elements)

		self.breadth = 100

		if elements.has_key('--sport'):
			self.sport = elements['--sport']
			del elements['--sport']
			self.breadth += 1000
		else:
			self.sport = None

		if elements.has_key('--dport'):
			self.dport = elements['--dport']
			del elements['--dport']
			self.breadth += 1000
		else:
			self.dport = None

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name, self.sport, self.dport]

class MatchMultiport(Match):

	idx = "MULTIPORT"

	def __str__(self):
		retVal = "-m multiport"

		if self.sports is not None:
			retVal = "{} --sports {}".format(retVal, ','.join(self.sports))

		if self.dports is not None:
			retVal = "{} --dports {}".format(retVal, ','.join(self.dports))

		return retVal

	def __gt__(self, match):
		"""
		Compute if

			self > match

		i.e. if we are more general version of match
		"""

		if self.sports is not None and match.sports is None:
			return False

		if (self.sports is None and match.sports is not None) or (self.sports is None and match.sports is None):
			return True

		if self.dports is not None and match.dports is None:
			return False

		if (self.dports is None and match.dports is not None) or (self.dports is None and match.dports is None):
			return True

		if len(set(match.sports) - set(self.sports)) > 0: return False

		if len(set(match.dports) - set(self.dports)) > 0: return False

		return True

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		return set(self.sports) == set(match.sports) and set(self.dports) == set(match.dports)

	def __ne__(self, match):
		return set(self.sports) != set(match.sports) or set(self.dports) != set(match.dports)

	def __init__(self, elements):

		super(MatchMultiport, self).__init__(elements)

		self.breadth = 0

		if elements.has_key('--sports'):
			self.sports = elements['--sports'].split(',')
			del elements['--sports']
			self.breadth += 1000 // len(self.sports)
		else:
			self.sports = []

		if elements.has_key('--dports'):
			self.dports = elements['--dports'].split(',')
			del elements['--dports']
			self.breadth += 1000 // len(self.dports)
		else:
			self.dports = []

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name] + self.sports + self.dports

class MatchState(Match):

	idx = "STATE"

	def __str__(self):
		return "-m state --state {}".format(','.join(self.states))

	def __gt__(self, match):
		"""
		Compute if

			self > match

		i.e. if we are more general version of match
		"""

		return len(set(match.states) - set(self.states)) == 0

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		return set(self.states) == set(match.states)

	def __ne__(self, match):
		return set(self.states) != set(match.states)

	def __init__(self, elements):

		super(MatchState, self).__init__(elements)

		self.breadth = 0

		self.states = elements['--state'].split(',')
		del elements['--state']
		self.breadth += 1000 // len(self.states)

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name] + sorted(self.states)

class MatchICMP(Match):

	idx = "ICMP"

	def __str__(self):
		return "-m icmp --icmp-type {}".format(self.icmp_type)

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		raise

	def __ne__(self, match):
		raise

	def __init__(self, elements):

		super(MatchICMP, self).__init__(elements)

		self.breadth = 100

		if elements.has_key('--icmp-type'):
			self.icmp_type = elements['--icmp-type']
			del elements['--icmp-type']
			self.breadth += 100
		else:
			self.icmp_type = 'all'

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name, self.icmp_type]

class MatchLimit(Match):

	idx = "LIMIT"

	def __str__(self):
		return "-m limit --limit {} --limit-burst {}".format(self.limit, self.limit_burst)

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		raise

	def __ne__(self, match):
		raise

	def __init__(self, elements):

		super(MatchLimit, self).__init__(elements)

		self.limit = None
		self.limit_burst = None

		self.breadth = 1

		if elements.has_key('--limit'):
			self.limit = elements['--limit']
			del elements['--limit']

		if elements.has_key('--limit-burst'):
			self.limit_burst = elements['--limit-burst']
			del elements['--limit-burst']

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

class MatchMAC(Match):

	idx = "MAC"

	def __str__(self):
		retVal = "-m mac"
		if self.mac_src is not None:
			retVal += " --mac-source {}".format(self.mac_src)

		if self.mac_dst is not None:
			retVal += " --mac-destination {}".format(self.mac_dst)

		return retVal

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		raise

	def __ne__(self, match):
		raise

	def __init__(self, elements):

		super(MatchMAC, self).__init__(elements)

		self.mac_src = None
		self.mac_dst = None

		self.breadth = 1

		if elements.has_key('--mac-source'):
			self.mac_src = elements['--mac-source']
			del elements['--mac-source']

		if elements.has_key('--mac-destination'):
			self.mac_dst = elements['--mac-destination']
			del elements['--mac-destination']

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

class MatchESP(Match):

	idx = "ESP"

	def __str__(self):
		return "-m esp"

	def __lt__(self, match):
		raise

	def __eq__(self, match):
		raise

	def __ne__(self, match):
		raise

	def __init__(self, elements):

		super(MatchESP, self).__init__(elements)

		self.breadth = 100

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name]

class MatchString(Match):

	idx = "STRING"

	def __str__(self):
		return "-m string --string {} --algo {} --to {}".format(self.string, self.algo, self.to)

	def __lt__(self, match):
		"""
		Compute if

			self < match

		i.e. if we are more general version of match

		Since this match is either equal or not, i.e. there is no _lt_ and _gt_
		it always returns False. Note that I assume self has a string match,
		otherwise, 
		"""
		return False

	def __gt_(self, match):
		raise

	def __eq__(self, match):
		return self.string == match.string and self.algo == match.algo and self.to == match.to

	def __ne__(self, match):
		raise

	def __init__(self, elements):

		super(MatchString, self).__init__(elements)

		self.breadth = 100

		if elements.has_key('--string'):
			self.string = elements['--string']
			del elements['--string']
		else:
			self.string = None

		if elements.has_key('--algo'):
			self.algo = elements['--algo']
			del elements['--algo']
		else:
			self.algo = None

		if elements.has_key('--to'):
			self.to = elements['--to']
			del elements['--to']
		else:
			self.to = None

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name]

class MatchIPRange(Match):

	idx = "IPRANGE"

	def __str__(self):
		return "-m iprange --src-range {} --dst-range {}".format(self.src_range, self.dst_range)

	def __lt__(self, match):
		"""
		Compute if

			self < match

		i.e. if we are more general version of match

		Since this match is either equal or not, i.e. there is no _lt_ and _gt_
		it always returns False. Note that I assume self has a string match,
		otherwise, 
		"""
		raise

	def __gt_(self, match):
		raise

	def __eq__(self, match):
		return self.src_range == match.src_range and self.dst_range == match.dst_range

	def __ne__(self, match):
		raise

	def __init__(self, elements):

		super(MatchIPRange, self).__init__(elements)

		self.breadth = 100

		if elements.has_key('--src-range'):
			self.src_range = elements['--src-range']
			del elements['--src-range']
		else:
			self.src_range = None

		if elements.has_key('--dst-range'):
			self.dst_range = elements['--dst-range']
			del elements['--dst-range']
		else:
			self.dst_range = None

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name]

class Selector(object):

	def __str__(self):
		retVal = ""

		if self.src is not None:
			if self.src[1]:
				retVal = "-s {}".format(self.src[0])
			else:
				retVal = "! -s {}".format(self.src[0])

		if self.dst is not None:
			if self.dst[1]:
				retVal = "{} -d {}".format(retVal, self.dst[0])
			else:
				retVal = "{} ! -d {}".format(retVal, self.dst[0])

		if self.inif is not None:
			if self.inif[1]:
				retVal = "{} -i {}".format(retVal, self.inif[0])
			else:
				retVal = "{} ! -i {}".format(retVal, self.inif[0])

		if self.outif is not None:
			if self.outif[1]:
				retVal = "{} -o {}".format(retVal, self.outif[0])
			else:
				retVal = "{} ! -o {}".format(retVal, self.outif[0])

		if self.proto is not None:
			if self.proto[1]:
				retVal = "{} -p {}".format(retVal, self.proto[0])
			else:
				retVal = "{} ! -p {}".format(retVal, self.proto[0])

		for key in self.matches:
			retVal += " " + str(self.matches[key])

		return retVal

	def matchFactory(self, elements):

		if elements['name'] == 'tcp':
			return MatchTCP(elements)
		elif elements['name'] == 'udp':
			return MatchUDP(elements)
		elif elements['name'] == 'multiport':
			return MatchMultiport(elements)
		elif elements['name'] == 'state':
			return MatchState(elements)
		elif elements['name'] == 'icmp':
			return MatchICMP(elements)
		elif elements['name'] == 'esp':
			return MatchESP(elements)
		elif elements['name'] == 'limit':
			return MatchLimit(elements)
		elif elements['name'] == 'mac':
			return MatchMAC(elements)
		elif elements['name'] == 'string':
			return MatchString(elements)
		elif elements['name'] == 'iprange':
			return MatchIPRange(elements)
		else:
			raise Exception("Unparsed match {}".format(elements['name']))

	def __init__(self):

		self.src = None
		self.dst = None
		self.inif = None
		self.outif = None
		self.proto = None
		self.proto_sport = None
		self.proto_dport = None
		self.matches = OrderedDict()

	def initializeFromIPTablesCommand(self, iptablesCommand):
		"""
		Initialize rule from IPTables command line. Return estimate of the
		breadth of the rule. The higher the returned value, the narrower rule
		is.
		"""

		breadth = 0

		if iptablesCommand.has_key('-s'):
			self.src = (ipaddr.IPNetwork(iptablesCommand['-s'][0]), iptablesCommand['-s'][1])
			del iptablesCommand['-s']

			breadth += self.src[0].prefixlen * 10

		if iptablesCommand.has_key('-d'):
			self.dst = (ipaddr.IPNetwork(iptablesCommand['-d'][0]), iptablesCommand['-d'][1])
			del iptablesCommand['-d']

			breadth += self.dst[0].prefixlen * 10

		if iptablesCommand.has_key('-i'):
			self.inif = iptablesCommand['-i']
			del iptablesCommand['-i']

			breadth += 100

		if iptablesCommand.has_key('-o'):
			self.outif = iptablesCommand['-o']
			del iptablesCommand['-o']

			breadth += 100

		if iptablesCommand.has_key('-p'):
			self.proto = iptablesCommand['-p']
			del iptablesCommand['-p']

			breadth += 100

		if iptablesCommand.has_key('-m'):

			for match in iptablesCommand['-m']:
				matchObject = self.matchFactory(match[0])
				self.matches[matchObject.idx] = matchObject
				breadth += matchObject.breadth

			del iptablesCommand['-m']

		return breadth

	def getSelectorTuple(self):

		selector = self.src + self.dst + self.inif + self.outif + self.proto

		for match in self.matches:
			selector += match.getMatch()

		return tuple(selector)

	def __eq__(self, selector):
		"""
		Check if the given selector is identical
		"""

		if self.src != selector.src:
			return False

		if self.dst != selector.dst:
			return False

		if self.inif != selector.inif:
			return False

		if self.outif != selector.outif:
			return False

		if self.proto != selector.proto:
			return False

		for matchKey in self.matches:
			if not selector.matches.has_key(matchKey):
				return False

			if self.matches[matchKey] != selector.matches[matchKey]:
				return False

		for matchKey in selector.matches:
			if not self.matches.has_key(matchKey):
				return False

		return True

	def __ne__(self, match):
		raise

	def __lt__(self, selector):
		raise

	def __le__(self, selector):
		raise

	def __ge__(self, selector):
		raise

	def __gt__(self, selector):
		"""
		Calculate the following expression:

			self > selector

		i.e. if we are more general than the given selector. Note that
		in the case False is returned, we don't know if selector > self,
		i.e. it doesn't have to be the case!
		"""

		# Return FALSE if both selectors are the same
		if self == selector: return False

		if self.src is not None and selector.src is None:
			return False

		# FIXME: This has a bug in case range is negated!
		if self.src is not None and selector.src is not None:

			if self.src[1] != selector.src[1]:
				return False

			non_negate = self.src[0]

			if not self.src[0].overlaps(selector.src[0]):
				return False

			if self.src[1] and self.src[0].prefixlen > selector.src[0].prefixlen:
				return False

			if not self.src[1] and self.src[0].prefixlen < selector.src[0].prefixlen:
				return False

		if self.dst is not None and selector.dst is None:
			return False

		# FIXME: This has a bug in case range is negated!
		if self.dst is not None and selector.dst is not None:

			if self.dst[1] != selector.dst[1]:
				return False

			if not self.dst[0].overlaps(selector.dst[0]):
				return False

			if selector.dst[1] and self.dst[0].prefixlen > selector.dst[0].prefixlen:
				return False

			if not self.dst[1] and self.dst[0].prefixlen < selector.dst[0].prefixlen:
				return False

		if (self.inif is not None and selector.inif is None) or self.inif != selector.inif:
			return False

		if (self.outif is not None and selector.outif is None) or self.outif != selector.outif:
			return False

		if self.proto is not None and selector.proto is None:
			return False

		if self.proto is not None and selector.proto is not None:

			# Check if protocols are different
			if self.proto[0] != selector.proto[0]:
				return False

			# Then, check if they are negated.
			if self.proto[1] != selector.proto[1]:
				return False

		for matchKey in self.matches:
			if not selector.matches.has_key(matchKey):
				return False

			if self.matches[matchKey] > selector.matches[matchKey]:
				continue

			return False

		return True

	def intersect(self, selector):
		newSelector = Selector()

		if self.src == None and selector.src != None:
			newSelector.src = selector.src
		elif self.src != None and selector.src == None:
			newSelector.src = self.src
		elif self.src == selector.src:
			newSelector.src = self.src
		else:
			raise ContradictingParameters("Contradicting selector for src in subrule ({},{})!".format(self.src, selector.src))

		if self.dst == None and selector.dst != None:
			newSelector.dst = selector.dst
		elif self.dst != None and selector.dst == None:
			newSelector.dst = self.dst
		elif self.dst == selector.dst:
			newSelector.dst = self.dst
		else:
			raise ContradictingParameters("Contradicting selector for dst in subrule ({},{})!".format(self.dst, selector.dst))

		if self.inif == None and selector.inif != None:
			newSelector.inif = selector.inif
		elif self.inif != None and selector.inif == None:
			newSelector.inif = self.inif
		elif self.inif == selector.inif:
			newSelector.inif = self.inif
		else:
			raise ContradictingParameters("Contradicting selector for inif in subrule ({},{})!".format(self.inif, selector.inif))

		if self.outif == None and selector.outif != None:
			newSelector.outif = selector.outif
		elif self.outif != None and selector.outif == None:
			newSelector.outif = self.outif
		elif self.outif == selector.outif:
			newSelector.outif = self.outif
		else:
			raise ContradictingParameters("Contradicting selector for outif in subrule ({},{})!".format(self.outif, selector.outif))

		if self.proto == None and selector.proto != None:
			newSelector.proto = selector.proto
		elif self.proto != None and selector.proto == None:
			newSelector.proto = self.proto
		elif self.proto == selector.proto:
			newSelector.proto = self.proto
		else:
			raise ContradictingParameters("Contradicting selector for proto in subrule ({},{})!".format(self.proto, selector.proto))

		for matchKey in self.matches:
			if not selector.matches.has_key(matchKey):
				newSelector.matches[matchKey] = self.matches[matchKey]
			else:
				raise ContradictingParameters("Duplicate and/or contradicting match options ({},{})!".format(self.matches[matchKey], selector.matches[matchKey]))

		for matchKey in selector.matches:
			if not self.matches.has_key(matchKey):
				newSelector.matches[matchKey] = selector.matches[matchKey]
			else:
				raise ContradictingParameters("Duplicate and/or contradicting match options ({},{})!".format(self.matches[matchKey], selector.matches[matchKey]))

		return newSelector

class Target(object):
	"""
	This is a class that abstracts target part of the IPTables rule, i.e.
	the part that is specified by -j option.

	This class has an attribute 'final' that specifies weather this is a
	final rule (True) or it jumps/calls some other rule (False)
	"""

	def __str__(self):

		if self.name == 'SNAT':
			ret = "-j SNAT --to-source " + str(self.to_source)
			if self.to_source_port:
				ret += ":" + self.to_source_port

		elif self.name == 'DNAT':
			ret = "-j DNAT --to-destination " + str(self.to_destination)
			if self.to_destination_port:
				ret += ":" + self.to_destination_port

		elif self.name == 'REJECT':

			ret = "-j REJECT"

		elif self.name == 'LOG':

			ret = "-j LOG"

		else:
			ret = "-j " + self.name

		return ret

	def __init__(self):
		self.name = 'UNKNOWN'

	def __eq__(self, target):

		if self.name != target.name:
			return False

		if self.name in ('ACCEPT', 'DROP', 'MASQUERADE', 'RETURN'):
			return True

		elif self.name == 'SNAT':
			return self.to_source == target.to_source and self.to_source_port == target.to_source_port

		elif self.name == 'DNAT':
			return self.to_destination == target.to_destination and self.to_destination_port == target.to_destination_port

		elif self.name == 'REJECT':
			return self.log_prefix == target.log_prefix

		elif self.name == 'LOG':

			if self.log_prefix != target.log_prefix:
				return False

			if self.log_prefix != target.log_prefix:
				return False

			if self.log_level != target.log_level:
				return False

			if self.log_tcp_options != target.log_tcp_options:
				return False

			return self.log_ip_options == target.log_ip_options

		else:
			raise Excpetion("Unknown target {}".format(self.name))

	def __ne__(self, match):
		raise

	def initializeFromIPTablesCommand(self, iptablesCommand):

		target = iptablesCommand['-j'][0]
		del iptablesCommand['-j']

		self.name = target['name']
		del target['name']
		self.final = False

		if self.name in ('ACCEPT', 'DROP', 'MASQUERADE', 'RETURN'):
			self.final = True

		elif self.name == 'SNAT':

			ip = target['--to-source']
			del target['--to-source']

			self.to_source_port = None
			try:
				self.to_source_port = ip[ip.rindex(':')+1:]
				ip = ip[:ip.rindex(':')]
			except:
				pass

			self.to_source = ipaddr.IPAddress(ip)
			self.final = True

		elif self.name == 'DNAT':

			ip = target['--to-destination']
			del target['--to-destination']

			self.to_destination_port = None
			try:
				self.to_destination_port = ip[ip.rindex(':')+1:]
				ip = ip[:ip.rindex(':')]
			except:
				pass

			self.to_destination = ipaddr.IPAddress(ip)
			self.final = True

		elif self.name == 'REJECT':

			if target.has_key('--reject-with'):
				self.log_prefix = target['--reject-with']
				del target['--reject-with']

			self.final = True

		elif self.name == 'LOG':

			if target.has_key('--log-prefix'):
				self.log_prefix = target['--log-prefix']
				del target['--log-prefix']
			else:
				self.log_prefix = None

			if target.has_key('--log-level'):
				self.log_level = target['--log-level']
				del target['--log-level']
			else:
				self.log_level = None

			if target.has_key('--log-tcp-options'):
				self.log_tcp_options = target['--log-tcp-options']
				del target['--log-tcp-options']
			else:
				self.log_tcp_options = None

			if target.has_key('--log-ip-options'):
				self.log_ip_options = target['--log-ip-options']
				del target['--log-ip-options']
			else:
				self.log_ip_options = None

			self.final = True

		if len(target) > 0:
			raise Exception("Unparsed target options {}".format(target))

class Rule(object):

	def __str__(self):
		retVal = ""
		if self.table is not None:
			retVal = "-t {}".format(self.table)

		if self.chain is not None:
			retVal = "{} -A {}".format(retVal, self.chain)

		return "{} {} {}".format(retVal, str(self.selector), str(self.target))

	def __init__(self, table = None, chain = None):
		self.selector = Selector()
		self.target = Target()
		self.lineAndFile = []
		self.breadth = None

		self.table = table
		self.chain = chain

	def __getattr__(self, name):
		if name == 'final':
			return self.target.final

		raise AttributeError("'Rule' object has no attribute '{}'".format(name))

	def __eq__(self, rule):
		if self.selector == rule.selector and self.target == rule.target:
			return True

		return False

	def __ne__(self, match):
		raise

	def __gt__(self, rule):
		"""
		Compute if the following condition hols:

			self > rule

		To be able to compare two rules, their targets have to be the same!
		"""
		if self.target == rule.target and  self.selector > rule.selector:
			return True

		return False

	def initializeFromIPTablesCommand(self, iptablesCommand):
		self.breadth = self.selector.initializeFromIPTablesCommand(iptablesCommand)
		self.target.initializeFromIPTablesCommand(iptablesCommand)

class Chain(object):

	def __init__(self, name, builtin = True, table = None):
		self.name = name
		self.rules = []
		self.policy = 'ACCEPT'
		self.builtin = builtin

		self.table = table

		# Indexes that group rules by different attributes
		self.rulesBySourceAddress = {}
		self.rulesByDestinationAddress = {}
		self.rulesByInputInterface = {}
		self.rulesByOutputInterface = {}

	def setPolicy(self, policy):
		self.policy = policy

	def insertRule(self, iptablesCommand, lineNumber, fileName):
		rule = Rule(self.table, self.name)
		rule.lineAndFile.append((fileName, lineNumber))
		rule.initializeFromIPTablesCommand(iptablesCommand)
		self.rules.insert(iptablesCommand['-I'][1], rule)

		if not self.rulesBySourceAddress.has_key(rule.selector.src):
			self.rulesBySourceAddress[rule.selector.src] = []
		self.rulesBySourceAddress[rule.selector.src].append(rule)

		if not self.rulesByDestinationAddress.has_key(rule.selector.dst):
			self.rulesByDestinationAddress[rule.selector.dst] = []
		self.rulesByDestinationAddress[rule.selector.dst].append(rule)

		if not self.rulesByInputInterface.has_key(rule.selector.inif):
			self.rulesByInputInterface[rule.selector.inif] = []
		self.rulesByInputInterface[rule.selector.inif].append(rule)

		if not self.rulesByOutputInterface.has_key(rule.selector.outif):
			self.rulesByOutputInterface[rule.selector.outif] = []
		self.rulesByOutputInterface[rule.selector.outif].append(rule)

		return rule

	def appendRule(self, iptablesCommand, lineNumber, fileName):
		rule = Rule(self.table, self.name)
		rule.lineAndFile.append((fileName, lineNumber))
		rule.initializeFromIPTablesCommand(iptablesCommand)
		self.rules.append(rule)

		if not self.rulesBySourceAddress.has_key(rule.selector.src):
			self.rulesBySourceAddress[rule.selector.src] = []
		self.rulesBySourceAddress[rule.selector.src].append(rule)

		if not self.rulesByDestinationAddress.has_key(rule.selector.dst):
			self.rulesByDestinationAddress[rule.selector.dst] = []
		self.rulesByDestinationAddress[rule.selector.dst].append(rule)

		if not self.rulesByInputInterface.has_key(rule.selector.inif):
			self.rulesByInputInterface[rule.selector.inif] = []
		self.rulesByInputInterface[rule.selector.inif].append(rule)

		if not self.rulesByOutputInterface.has_key(rule.selector.outif):
			self.rulesByOutputInterface[rule.selector.outif] = []
		self.rulesByOutputInterface[rule.selector.outif].append(rule)

		return rule

	def deleteRule(self, iptablesCommand):
		raise Exception('Rule removal not implemented!')

class Table(object):

	def __init__(self, name, chains):
		self.name = name
		self.chains = {}
		self.builtInChains = []
		for chain in chains:
			self.chains[chain] = Chain(chain, table = self.name)
			self.builtInChains.append(chain)

		# Indexes that group rules by different attributes
		self.rulesBySourceAddress = {}
		self.rulesByDestinationAddress = {}
		self.rulesByInputInterface = {}
		self.rulesByOutputInterface = {}

	def parseIPTablesCommand(self, iptablesCommand, lineNumber = None, fileName = None):

		rule = None

		if iptablesCommand.has_key('-P'):

			self.chains[iptablesCommand['-P'][0]].setPolicy(iptablesCommand['-P'][1])
			del iptablesCommand['-P']

		elif iptablesCommand.has_key('-N'):

			self.chains[iptablesCommand['-N'][0]] = Chain(iptablesCommand['-N'][0], False, table = self.name)
			del iptablesCommand['-N']

		elif iptablesCommand.has_key('-I'):

			rule = self.chains[iptablesCommand['-I'][0]].insertRule(iptablesCommand, lineNumber, fileName)
			del iptablesCommand['-I']

			# FIXME: Inserting should put it into the first position!!!
			# Also, if there is an index, it has to be taken into account too!
			if not self.rulesBySourceAddress.has_key(rule.selector.src):
				self.rulesBySourceAddress[rule.selector.src] = []
			self.rulesBySourceAddress[rule.selector.src].append(rule)

			if not self.rulesByDestinationAddress.has_key(rule.selector.dst):
				self.rulesByDestinationAddress[rule.selector.dst] = []
			self.rulesByDestinationAddress[rule.selector.dst].append(rule)

			if not self.rulesByInputInterface.has_key(rule.selector.inif):
				self.rulesByInputInterface[rule.selector.inif] = []
			self.rulesByInputInterface[rule.selector.inif].append(rule)

			if not self.rulesByOutputInterface.has_key(rule.selector.outif):
				self.rulesByOutputInterface[rule.selector.outif] = []
			self.rulesByOutputInterface[rule.selector.outif].append(rule)

		elif iptablesCommand.has_key('-A'):

			rule = self.chains[iptablesCommand['-A'][0]].appendRule(iptablesCommand, lineNumber, fileName)
			del iptablesCommand['-A']

			if not self.rulesBySourceAddress.has_key(rule.selector.src):
				self.rulesBySourceAddress[rule.selector.src] = []
			self.rulesBySourceAddress[rule.selector.src].append(rule)

			if not self.rulesByDestinationAddress.has_key(rule.selector.dst):
				self.rulesByDestinationAddress[rule.selector.dst] = []
			self.rulesByDestinationAddress[rule.selector.dst].append(rule)

			if not self.rulesByInputInterface.has_key(rule.selector.inif):
				self.rulesByInputInterface[rule.selector.inif] = []
			self.rulesByInputInterface[rule.selector.inif].append(rule)

			if not self.rulesByOutputInterface.has_key(rule.selector.outif):
				self.rulesByOutputInterface[rule.selector.outif] = []
			self.rulesByOutputInterface[rule.selector.outif].append(rule)

		elif iptablesCommand.has_key('-F'):

			print "Warning: Ignorig -F command"
			del iptablesCommand['-F']

		elif iptablesCommand.has_key('-D'):

			print "Warning: Ignorig -D command"
			del iptablesCommand['-D']

		else:
			raise ParsingException("Unrecognized command {}".format(iptablesCommand))

		if len(iptablesCommand) > 0:
			raise ParsingException("Unparsed argument(s): {}".format(''.join(iptablesCommand)))

		return rule

	def _flattenRule(self, rule, subrule, supressErrors):

		try:

			clonedRule = Rule()
			clonedRule.breadth = rule.breadth + subrule.breadth
			clonedRule.totalBreadth = rule.breadth + subrule.breadth
			clonedRule.selector = rule.selector.intersect(subrule.selector)
			clonedRule.target = subrule.target
			clonedRule.lineAndFile = rule.lineAndFile + subrule.lineAndFile

			if subrule.final:
				yield clonedRule
				return

		except ContradictingParameters, err:
			if not supressErrors:
				print "Error in rules in {} and {}".format(rule.lineAndFile, subrule.lineAndFile)
			return

		for subsubrule in self.chains[subrule.target.name].rules:
			for flattenedRule in self._flattenRule(clonedRule, subsubrule, supressErrors):
				yield flattenedRule


	def getFlattenedRules(self, chain, CSV = False, supressErrors = False):

		for rule in self.chains[chain].rules:

			if rule.final:
				rule.totalBreadth = rule.breadth
				yield rule
				continue

			for subrule in self.chains[rule.target.name].rules:
				for flattenedRule in self._flattenRule(rule, subrule, supressErrors):
					yield flattenedRule

class Firewall(object):

	def __init__(self):

		self.tables = {
			'filter': Table('FILTER', ['INPUT', 'OUTPUT', 'FORWARD']),
			'nat': Table('NAT', ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING']),
			'mangle': Table('MANGLE', ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING']),
			'raw': Table('RAW', ['PREROUTING', 'OUTPUT'])
		}

		# Indexes that group rules by different attributes
		self.rulesBySourceAddress = {}
		self.rulesByDestinationAddress = {}
		self.rulesByInputInterface = {}
		self.rulesByOutputInterface = {}

	def loadTopologyFromFile(self, topologyFile):
		"""
		Load a topology from file
		"""
		config = ConfigParser.ConfigParser()
		config.readfp(topologyFile)

		for section in config.sections():
			print "[{}]".format(section)
			for option in config.options(section):
				print "{}={}".format(option, config.get(section, option))

	def generateTopology(self):
		"""
		Generate topology description and return it in a string
		"""
		print "[General]"
		print "description = Automatically generated topology"

		interfaces = set()
		for interface in self.rulesByInputInterface.keys():
			if interface is not None: interfaces.add(interface[0])

		for interface in self.rulesByOutputInterface.keys():
			if interface is not None: interfaces.add(interface[0])

		print "interfaces = {}".format(" ".join(interfaces))
		print

		for interface in interfaces:
			print "[{}]".format(interface)
			print

	def parseMatch(self, matchType, elements):

		match = {}
		match['name'] = matchType

		if matchType in ('tcp', 'udp'):

			while True and len(elements) > 0:

				if elements[0] == '--sport':
					elements.pop(0)
					match['--sport'] = elements.pop(0)
				elif elements[0] == '--dport':
					elements.pop(0)
					match['--dport'] = elements.pop(0)
				else:
					break

		elif matchType  == 'mac':

			while True and len(elements) > 0:

				if elements[0] == '--mac-source':
					elements.pop(0)
					match['--mac-source'] = elements.pop(0)
				elif elements[0] == '--mac-destination':
					elements.pop(0)
					match['--mac-destination'] = elements.pop(0)
				else:
					break

		elif matchType == 'icmp':

			if elements[0] == '--icmp-type':
				elements.pop(0)
				match['--icmp-type'] = elements.pop(0)

		elif matchType == 'multiport':

			while len(elements) > 0:

				if elements[0] == '--sports':
					elements.pop(0)
					match['--sports'] = elements.pop(0)
				elif elements[0] == '--dports':
					elements.pop(0)
					match['--dports'] = elements.pop(0)
				else:
					break

		elif matchType == 'state':

			if elements[0] == '--state':
				elements.pop(0)
				match['--state'] = elements.pop(0)
			else:
				raise ParsingException("Expected state type match")

		elif matchType == 'esp':
			pass

		elif matchType == 'limit':

			while len(elements) > 0:

				if elements[0] == '--limit':
					match['--limit'] = elements[1]
					elements.pop(0)
					elements.pop(0)
					continue

				if elements[0] == '--limit-burst':
					match['--limit-burst'] = elements[1]
					elements.pop(0)
					elements.pop(0)
					continue

				break

		elif matchType == 'string':

			while len(elements) > 0:

				if elements[0] == '--string':
					match['--string'] = elements[1]
					elements.pop(0)
					elements.pop(0)
					continue

				if elements[0] == '--algo':
					match['--algo'] = elements[1]
					elements.pop(0)
					elements.pop(0)
					continue

				if elements[0] == '--to':
					match['--to'] = elements[1]
					elements.pop(0)
					elements.pop(0)
					continue

				break

		elif matchType == 'iprange':

			negate = False
			while len(elements) > 0:

				if elements[0] == '!':
					negate = True
					elements.pop(0)
					continue

				if elements[0] == '--src-range':
					match['--src-range'] = (elements[1], negate)
					elements.pop(0)
					elements.pop(0)
					continue

				if elements[0] == '--dst-range':
					match['--dst-range'] = (elements[1], negate)
					elements.pop(0)
					elements.pop(0)
					continue

				break

		else:
			raise ParsingException("Unknown match type {}".format(matchType))

		return (match, )

	def parseTarget(self, targetType, elements):

		target = {}
		target['name'] = targetType

		if targetType in ('ACCEPT', 'DROP', 'MASQUERADE', 'RETURN'):
			pass

		elif targetType == 'DNAT':

			if elements[0] == '--to-destination':
				elements.pop(0)
				target['--to-destination'] = elements.pop(0)
			elif elements[0] == '--to':
				elements.pop(0)
				target['--to-destination'] = elements.pop(0)
			else:
				raise ParsingException("Expected --to-destination/--to argument")

		elif targetType == 'SNAT':

			if elements[0] == '--to-source':
				elements.pop(0)
				target['--to-source'] = elements.pop(0)
			else:
				raise ParsingException("Expected --to-source argument")

		elif targetType == 'REJECT':

			while True and len(elements) > 0:

				if elements[0] == '--reject-with':
					elements.pop(0)
					target['--reject-with'] = elements.pop(0)
				else:
					raise ParsingException("Leftover unparsed arguments {}".format(elements))

		elif targetType == 'LOG':

			while True and len(elements) > 0:

				if elements[0] == '--log-prefix':
					elements.pop(0)
					target['--log-prefix'] = elements.pop(0)
				elif elements[0] == '--log-level':
					elements.pop(0)
					target['--log-level'] = elements.pop(0)
				elif elements[0] == '--log-tcp-options':
					elements.pop(0)
					target['--log-tcp-options'] = True
				elif elements[0] == '--log-ip-options':
					elements.pop(0)
					target['--log-ip-options'] = True
				else:
					raise ParsingException("Leftover unparsed arguments {}".format(elements))

		else:
			pass

		return (target, )

	def addIPTablesCLILine(self, line, lineNumber = 0, fileName = None):

		# First, split the line into components taking care of strings
		elements = shlex.split(line)

 		# Drop command line element if it is iptables command
		if len(elements[0]) >= 8 and elements[0][-8:] == 'iptables':
			elements.pop(0)

		# Traverse components and build up dictionary.
		# Dictionary has as a key commands and options, and the values of
		# the dictionary are their options and subcommands.
		iptablesCommand = {}
		nonnegate = True
		while elements:
			key = elements.pop(0)
			if key == '!':
				nonnagate = False
				continue

			if key == '-m':
				matchType = elements.pop(0)
				if not iptablesCommand.has_key('-m'):
					iptablesCommand['-m'] = []
				iptablesCommand['-m'].append(self.parseMatch(matchType, elements))

			elif key == '-p':
				protocol = elements.pop(0)
				iptablesCommand['-p'] = (protocol, nonnegate)

				if elements[0] != '-m':
					elements.insert(0, protocol)
					elements.insert(0, '-m')

			elif key == '-j':
				targetType = elements.pop(0)
				iptablesCommand['-j'] = self.parseTarget(targetType, elements)

			elif key == '-P':
				iptablesCommand[key] = (elements.pop(0), elements.pop(0))

			elif key == '-F':
				if len(elements) > 0 and elements[0][0] != '-':
					iptablesCommand[key] = [elements.pop(0), None]
				else:
					iptablesCommand[key] = (None, None)

			elif key == '-I':
				iptablesCommand[key] = (elements.pop(0), 0)
				if elements[0][0] != '-':
					iptablesCommand[key] = (iptablesCommand[key][0], int(elements.pop(0)))

			else:
				iptablesCommand[key] = (elements.pop(0), nonnegate)
				if len(elements) > 0:
					param = iptablesCommand[key][0]
					if param[-1] == '!':
						iptablesCommand[key] = (elements.pop(0), False)
					else:
						nextToken = elements.pop(0)
						if nextToken[0] != '-':
							iptablesCommand[key] = (iptablesCommand[key][0], nextToken)
						else:
							elements.insert(0, nextToken)

			nonnegate = True

		if iptablesCommand.has_key('-t'):
			table = iptablesCommand['-t'][0]
			del iptablesCommand['-t']
		else:
			table = 'filter'

		rule = self.tables[table].parseIPTablesCommand(iptablesCommand, lineNumber, fileName)

		if rule is not None:

			if not self.rulesBySourceAddress.has_key(rule.selector.src):
				self.rulesBySourceAddress[rule.selector.src] = []
			self.rulesBySourceAddress[rule.selector.src].append(rule)

			if not self.rulesByDestinationAddress.has_key(rule.selector.dst):
				self.rulesByDestinationAddress[rule.selector.dst] = []
			self.rulesByDestinationAddress[rule.selector.dst].append(rule)

			if not self.rulesByInputInterface.has_key(rule.selector.inif):
				self.rulesByInputInterface[rule.selector.inif] = []
			self.rulesByInputInterface[rule.selector.inif].append(rule)

			if not self.rulesByOutputInterface.has_key(rule.selector.outif):
				self.rulesByOutputInterface[rule.selector.outif] = []
			self.rulesByOutputInterface[rule.selector.outif].append(rule)

	def addIPTablesLoadSavedStream(self, fileName, stream):
		"""
		This method expects iterator object, stream, that has method readlines().
		Method readlines() should return line by line of input stream, where
		each line output produced by iptables-save command.

		FIXME: This is hacked method. Loading rules has to be
			refactored/optimized
		"""

		lineNumber = 0
		for line in stream.readlines():
			lineNumber += 1
			if line[0] == '#' or line[0] == '\n': continue

			if line[0] == '*':
				table = line[1:]
				continue

			if line[0] == ':':
				args = line[1:].split()
				if args[1] == '-':
					self.addIPTablesCLILine("iptables -t {} -N {}".format(table, args[0]), lineNumber, fileName)
				else:
					self.addIPTablesCLILine("iptables -t {} -P {} {}".format(table, args[0], args[1]), lineNumber, fileName)
				continue

			if line[:6] == 'COMMIT':
				continue

			try:
				self.addIPTablesCLILine("iptables -t {} {}".format(table, line), lineNumber, fileName)
			except ParsingException as detail:
				print "Parsing error '{}' in line {}:{}".format(detail, fileName, lineNumber)
				# TODO: Add ignore errors parameter
				return

	def addIPTablesLoadCLIStream(self, fileName, stream):
		"""
		This method expects iterator object, stream, that has method readlines().
		Method readlines() should return line by line of input stream, where
		each line is a full iptables command as typed in command line.
		"""

		lineNumber = 0
		for line in stream.readlines():
			lineNumber += 1
			if line[0] == '#' or line[0] == '\n': continue

			try:
				self.addIPTablesCLILine(line, lineNumber, fileName)
			except ParsingException as detail:
				print "Parsing error '{}' in line {}:{}".format(detail, fileName, lineNumber)
				# TODO: Add ignore errors parameter
				return

def checkContradictingRules(firewall):
	"""
	This method flattens all the rules in the firewall to builtin chains
	and then searches for contradictions in rules that call subchains and
	rules in subchains.
	"""

	for table in firewall.tables:
		for chain in firewall.tables[table].builtInChains:
			for flattenedRule in firewall.tables[table].getFlattenedRules(chain):
				pass

def checkDuplicateRules(firewall):
	"""
	This method iterates over rules in each table/chain combination and
	searches for duplicate rules
	"""
	for table in firewall.tables:
		for chain in firewall.tables[table].chains:
			numRules = len(firewall.tables[table].chains[chain].rules)
			for idx in xrange(numRules):
				baseRule = firewall.tables[table].chains[chain].rules[idx]
				for idx2 in xrange(idx + 1, numRules):
					compRule = firewall.tables[table].chains[chain].rules[idx2]
					if compRule == baseRule:
						print "Duplicate rules in {} and {}".format(baseRule.lineAndFile, compRule.lineAndFile)

def checkSupersetRules(firewall):
	"""
	This method searches for more general rule followed by a more
	specific one
	"""
	for table in firewall.tables:
		for chain in firewall.tables[table].chains:
			numRules = len(firewall.tables[table].chains[chain].rules)
			for idx in xrange(numRules):
				baseRule = firewall.tables[table].chains[chain].rules[idx]
				for idx2 in xrange(idx + 1, numRules):
					compRule = firewall.tables[table].chains[chain].rules[idx2]
					if baseRule > compRule:
						print "Superset rule in {} over rule in {}".format(baseRule.lineAndFile, compRule.lineAndFile)

def checkNetworkMasks(firewall):
	"""
	This method checks networks and IP addresses for mistakes like the
	following ones:

		192.168.1.1/0
		192.168.1.0/16

	It is obvious that there is an error in the previous specifications.
	"""
	for table in firewall.tables:
		for chain in firewall.tables[table].chains:
			for rule in firewall.tables[table].chains[chain].rules:
				if rule.selector.src and str(rule.selector.src[0]) != str(rule.selector.src[0].masked()):
					print "Suspicious src '{}' in {}".format(rule.selector.src[0], rule.lineAndFile)

				if rule.selector.dst and str(rule.selector.dst[0]) != str(rule.selector.dst[0].masked()):
					print "Suspicious dst '{}' in {}".format(rule.selector.dst[0], rule.lineAndFile)

def dumpAllChains(firewall, CSV = False):
	"""
	Dump names of all chains in the firewall
	"""
	for table in firewall.tables:
		if not CSV: print table
		for chain in firewall.tables[table].chains:
			if CSV:
				print "{},{}".format(table, chain)
			else:
				print "\t{}".format(chain)

def dumpAllRulesPerChainAndTable(firewall, CSV = False):
	"""
	This method dumps all rules grouped by chains and rules
	"""
	for table in firewall.tables:
		if not CSV: print table
		for chain in firewall.tables[table].chains:
			if not CSV: print "\t{}".format(chain)
			for rule in firewall.tables[table].chains[chain].rules:
				if CSV:
					print "{},{},{}".format(rule.lineAndFile, rule.breadth, rule)
				else:
					print "\t\t{:5} ({}): {}".format(rule.lineAndFile, rule.breadth, rule)

def dumpAllFlattenedRules(firewall, CSV = False, suppressErrors = True):
	"""
	Flattens and dumps all rules so that all of them appear as if in
	built in chains. This can catch contradictions, i.e. rule in a
	subchain has a contradictory match against rule in a chain that calls
	subchain.
	"""

	for table in firewall.tables:
		if not CSV: print "{}".format(table)
		for chain in firewall.tables[table].builtInChains:
			if not CSV: print "\t{}".format(chain)
			for flattenedRule in firewall.tables[table].getFlattenedRules(chain, CSV, suppressErrors):
				if CSV:
					print "{},{},{}".format(flattenedRule.totalBreadth, flattenedRule.lineAndFile, flattenedRule)
				else:
					print "\t\t({}) {} {}".format(flattenedRule.totalBreadth, flattenedRule.lineAndFile, flattenedRule)
			if not CSV: print

def dumpAllRulesBySourceAddress(firewall, CSV = False):
	"""
	Dump all rules grouped by a source address
	"""
	for source in firewall.rulesBySourceAddress:
		print source
		for rule in firewall.rulesBySourceAddress[source]:
			print "\t{}".format(rule)

def dumpAllRulesByDestinationAddress(firewall, CSV = False):
	"""
	Dump all rules grouped by a destination address
	"""
	for destination in firewall.rulesByDestinationAddress:
		print destination
		for rule in firewall.rulesByDestinationAddress[destination]:
			print "\t{}".format(rule)

def dumpAllRulesByInputInterface(firewall, CSV = False):
	"""
	Dump all rules grouped by input interface
	"""
	for inif in firewall.rulesByInputInterface:
		print inif
		for rule in firewall.rulesByInputInterface[inif]:
			print "\t{}".format(rule)

def dumpAllRulesByOutputInterface(firewall, CSV = False):
	"""
	Dump all rules grouped by input interface
	"""
	for outif in firewall.rulesByOutputInterface:
		print outif
		for rule in firewall.rulesByOutputInterface[outif]:
			print "\t{}".format(rule)

def main():

	import argparse

	parser = argparse.ArgumentParser(description='IPTables Firewall checker')
	parser.add_argument('files', metavar='file', type=str, nargs='+', help='files with firewall rules')
	parser.add_argument('-a', '--check-all', action='store_true', help='perform all checks')
	parser.add_argument('-c', '--iptables-cli', action='store_true', help='assume input files are in iptables command line format (default)')
	parser.add_argument('-d', '--dump-all', action='store_true', help='dump all data in different views')
	parser.add_argument('-m', '--merge', action='store_true', help='should all input files be merged (default: process separately)')
	parser.add_argument('-s', '--iptables-save', action='store_true', help='assume input files are in iptables-save format')
	parser.add_argument('-t', '--topology', nargs=1, dest='topology_file', type=file, help='INI file describing topology')
	parser.add_argument('--dump-csv-format', action='store_true', help='dump is in CSV format')

	args = parser.parse_args()

	for fwFileName in args.files:

		firewall = Firewall()

		if args.topology_file is not None:
			firewall.loadTopologyFromFile(args.topology_file[0])

		if args.merge:

			for fwFileName in args.files:
				with open(fwFileName) as f:
					if args.iptables_save:
						firewall.addIPTablesLoadSavedStream(fwFileName, f)
					else:
						firewall.addIPTablesLoadCLIStream(fwFileName, f)

		else:

			print "Processing file {}".format(fwFileName)

			with open(fwFileName) as f:
				if args.iptables_save:
					firewall.addIPTablesLoadSavedStream(fwFileName, f)
				else:
					firewall.addIPTablesLoadCLIStream(fwFileName, f)

		if args.dump_all:
			print "Dumping all rules organized per chain and per table"
			print "==================================================="
			dumpAllRulesPerChainAndTable(firewall, args.dump_csv_format)
			print

		if args.dump_all:
			print "Dumping all rules organized per source address/network in rule"
			print "=============================================================="
			dumpAllRulesBySourceAddress(firewall, args.dump_csv_format)
			print

		if args.dump_all:
			print "Dumping all rules organized per destination address/network in rule"
			print "==================================================================="
			dumpAllRulesByDestinationAddress(firewall, args.dump_csv_format)
			print

		if args.dump_all:
			print "Dumping all rules flattened into builtin chains"
			print "==============================================="
			dumpAllFlattenedRules(firewall, args.dump_csv_format)
			print

		if args.check_all:
			print "Check network masks"
			print "==================="
			checkNetworkMasks(firewall)
			print

		if args.check_all:
			print "Checking contradicting rules"
			print "============================"
			checkContradictingRules(firewall)
			print

		if args.check_all:
			print "Checking duplicate rules"
			print "========================"
			checkDuplicateRules(firewall)
			print

		if args.check_all:
			print "Checking overlapping rules"
			print "=========================="
			checkSupersetRules(firewall)

		if args.merge: break

if __name__ == '__main__':
	main()
