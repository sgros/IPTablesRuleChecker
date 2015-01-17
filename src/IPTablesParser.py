#!/usr/bin/python

import sys
import re
import ipaddr
import shlex
from collections import OrderedDict

class ContradictingParameters(Exception): pass
class ForbiddedCommand(Exception): pass
class UnexpectedCondition(Exception): pass
class UnparsableLine(Exception): pass
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

	def __init__(self, elements):

		super(MatchTCP, self).__init__(elements)

		if elements.has_key('--sport'):
			self.sport = elements['--sport']
			del elements['--sport']
		else:
			self.sport = None

		if elements.has_key('--dport'):
			self.dport = elements['--dport']
			del elements['--dport']
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

	def __init__(self, elements):

		super(MatchUDP, self).__init__(elements)

		if elements.has_key('--sport'):
			self.sport = elements['--sport']
			del elements['--sport']
		else:
			self.sport = None

		if elements.has_key('--dport'):
			self.dport = elements['--dport']
			del elements['--dport']
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
			retVal = "{} --sports {}".format(retVal, self.sports)

		if self.dports is not None:
			retVal = "{} --dports {}".format(retVal, self.dports)

		return retVal

	def __init__(self, elements):

		super(MatchMultiport, self).__init__(elements)

		if elements.has_key('--sports'):
			self.sports = elements['--sports'].split(',')
			del elements['--sports']
		else:
			self.sports = None

		if elements.has_key('--dports'):
			self.dports = elements['--dports'].split(',')
			del elements['--dports']
		else:
			self.dports = None

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name] + self.sports + self.dports

class MatchState(Match):

	idx = "STATE"

	def __str__(self):
		return "-m state --state {}".format(','.join(self.states))

	def __init__(self, elements):

		super(MatchState, self).__init__(elements)

		self.states = elements['--state'].split(',')
		del elements['--state']

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

	def getMatch(self):
		return [self.name] + sorted(self.states)

class MatchICMP(Match):

	idx = "ICMP"

	def __str__(self):
		return "-m icmp --icmp-type {}".format(self.icmp_type)

	def __init__(self, elements):

		super(MatchICMP, self).__init__(elements)

		if elements.has_key('--icmp-type'):
			self.icmp_type = elements['--icmp-type']
			del elements['--icmp-type']
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

	def __init__(self, elements):

		super(MatchLimit, self).__init__(elements)

		self.limit = None
		self.limit_burst = None

		if elements.has_key('--limit'):
			self.limit = elements['--limit']
			del elements['--limit']

		if elements.has_key('--limit-burst'):
			self.limit_burst = elements['--limit-burst']
			del elements['--limit-burst']

		if len(elements) > 0:
			raise Exception("Unparsed state options {}".format(elements))

class MatchESP(Match):

	idx = "ESP"

	def __str__(self):
		return "-m esp"

	def __init__(self, elements):

		super(MatchESP, self).__init__(elements)

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
				retVal = "{} -o {}".format(retVal, self.proto[0])
			else:
				retVal = "{} ! -o {}".format(retVal, self.proto[0])

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

		if iptablesCommand.has_key('-s'):
			self.src = (ipaddr.IPNetwork(iptablesCommand['-s'][0]), iptablesCommand['-s'][1])
			del iptablesCommand['-s']

		if iptablesCommand.has_key('-d'):
			self.dst = (ipaddr.IPNetwork(iptablesCommand['-d'][0]), iptablesCommand['-d'][1])
			del iptablesCommand['-d']

		if iptablesCommand.has_key('-i'):
			self.inif = iptablesCommand['-i']
			del iptablesCommand['-i']

		if iptablesCommand.has_key('-o'):
			self.outif = iptablesCommand['-o']
			del iptablesCommand['-o']

		if iptablesCommand.has_key('-p'):
			self.proto = iptablesCommand['-p']
			del iptablesCommand['-p']

		if iptablesCommand.has_key('-m'):

			for match in iptablesCommand['-m']:
				matchObject = self.matchFactory(match[0])
				self.matches[matchObject.idx] = matchObject

			del iptablesCommand['-m']

	def getSelectorTuple(self):

		selector = self.src + self.dst + self.inif + self.outif + self.proto

		for match in self.matches:
			selector += match.getMatch()

		return tuple(selector)

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

		elif self.name == 'DNAT':
			ret = "-j DNAT --to-destination " + str(self.to_destination)

		elif self.name == 'REJECT':

			ret = "-j REJECT"

		elif self.name == 'LOG':

			ret = "-j LOG"

		else:
			ret = "-j " + self.name

		return ret

	def __init__(self):
		self.name = 'UNKNOWN'

	def initializeFromIPTablesCommand(self, iptablesCommand):

		target = iptablesCommand['-j'][0]
		del iptablesCommand['-j']

		self.name = target['name']
		del target['name']
		self.final = False

		if self.name in ('ACCEPT', 'DROP'):
			self.final = True

		elif self.name == 'SNAT':

			self.to_source = ipaddr.IPAddress(target['--to-source'])
			del target['--to-source']
			self.final = True

		elif self.name == 'DNAT':

			self.to_destination = ipaddr.IPAddress(target['--to-destination'])
			del target['--to-destination']
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

			if target.has_key('--log-level'):
				self.log_level = target['--log-level']
				del target['--log-level']

			if target.has_key('--log-tcp-options'):
				self.log_level = target['--log-tcp-options']
				del target['--log-tcp-options']

			if target.has_key('--log-ip-options'):
				self.log_level = target['--log-ip-options']
				del target['--log-ip-options']

			self.final = True

		if len(target) > 0:
			raise Exception("Unparsed target options {}".format(target))

class Rule(object):

	def __str__(self):
		return str(self.selector) + " " + str(self.target)

	def __init__(self):
		self.selector = Selector()
		self.target = Target()
		self.lineNumber = None

	def __getattr__(self, name):
		if name == 'final':
			return self.target.final

		raise AttributeError("'Rule' object has no attribute '{}'".format(name))

	def initializeFromIPTablesCommand(self, iptablesCommand):
		self.selector.initializeFromIPTablesCommand(iptablesCommand)
		self.target.initializeFromIPTablesCommand(iptablesCommand)

	def setLineNumber(self, lineNumber):
		self.lineNumber = lineNumber

class Chain(object):

	def __init__(self, name, builtin = True):
		self.name = name
		self.rules = []
		self.policy = 'ACCEPT'
		self.builtin = builtin

	def setPolicy(self, policy):
		self.policy = policy

	def insertRule(self, iptablesCommand, lineNumber):
		rule = Rule()
		rule.setLineNumber(lineNumber)
		rule.initializeFromIPTablesCommand(iptablesCommand)
		self.rules.insert(iptablesCommand['-I'][1], rule)

	def appendRule(self, iptablesCommand, lineNumber):
		rule = Rule()
		rule.setLineNumber(lineNumber)
		rule.initializeFromIPTablesCommand(iptablesCommand)
		self.rules.append(rule)

	def deleteRule(self, iptablesCommand):
		raise Exception('Rule removal not implemented!')

class Table(object):

	def __init__(self, name, chains):
		self.name = name
		self.chains = {}
		self.builtInChains = []
		for chain in chains:
			self.chains[chain] = Chain(chain)
			self.builtInChains.append(chain)

	def parseIPTablesCommand(self, iptablesCommand, lineNumber = None):

		if iptablesCommand.has_key('-P'):

			self.chains[iptablesCommand['-P'][0]].setPolicy(iptablesCommand['-P'][1])
			del iptablesCommand['-P']

		elif iptablesCommand.has_key('-N'):

			self.chains[iptablesCommand['-N'][0]] = Chain(iptablesCommand['-N'][0], False)
			del iptablesCommand['-N']

		elif iptablesCommand.has_key('-I'):

			self.chains[iptablesCommand['-I'][0]].insertRule(iptablesCommand, lineNumber)
			del iptablesCommand['-I']

		elif iptablesCommand.has_key('-A'):

			self.chains[iptablesCommand['-A'][0]].appendRule(iptablesCommand, lineNumber)
			del iptablesCommand['-A']

		elif iptablesCommand.has_key('-F'):

			print "Warning: Ignorig -F command"
			del iptablesCommand['-F']

		else:
			raise Exception("Unrecognized command {}".format(iptablesCommand))

		if len(iptablesCommand) > 0:
			raise UnparsableLine("Unparsed argument(s): {}".format(''.join(iptablesCommand)))

	def getFlattenedRules(self, chain):

		for rule in self.chains[chain].rules:

			if rule.final:
				yield rule
				continue

			for subrule in self.chains[rule.target.name].rules:

				try:
					clonedRule = Rule()
					clonedRule.selector = rule.selector.intersect(subrule.selector)
					clonedRule.target = subrule.target
				except Exception as detail:
					print "Pogreska u pravilu u liniji {} i liniji {}".format(rule.lineNumber, subrule.lineNumber)
					continue

				yield clonedRule

class Firewall(object):

	def __init__(self):

		self.tables = {
			'filter': Table('FILTER', ['INPUT', 'OUTPUT', 'FORWARD']),
			'nat': Table('NAT', ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING']),
			'mangle': Table('MANGLE', ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING']),
			'raw': Table('RAW', ['PREROUTING', 'OUTPUT'])
		}

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
				raise UnparsableLine("Expected state type match")

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

		else:
			raise UnparsableLine("Unknown match type {}".format(matchType))

		return (match, )

	def parseTarget(self, targetType, elements):

		target = {}
		target['name'] = targetType

		if targetType in ('ACCEPT', 'DROP'):
			pass

		elif targetType == 'DNAT':

			if elements[0] == '--to-destination':
				elements.pop(0)
				target['--to-destination'] = elements.pop(0)
			else:
				raise UnparsableLine("Expected --to-destination argument")

		elif targetType == 'SNAT':

			if elements[0] == '--to-source':
				elements.pop(0)
				target['--to-source'] = elements.pop(0)
			else:
				raise UnparsableLine("Expected --to-source argument")

		elif targetType == 'REJECT':

			while True and len(elements) > 0:

				if elements[0] == '--reject-with':
					elements.pop(0)
					target['--reject-with'] = elements.pop(0)
				else:
					raise UnparsableLine("Leftover unparsed arguments {}".format(elements))

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
					raise UnparsableLine("Leftover unparsed arguments {}".format(elements))

		else:
			pass

		return (target, )

	def addIPTablesLine(self, line, lineNumber = 0):

		# First, split the line into components taking care of strings
		elements = shlex.split(line)

 		# Drop command line element
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
				iptablesCommand['-p'] = [protocol, nonnegate, None, None]
				while len(elements) > 0:

					if elements[0] == '--sport':
						elements.pop(0)
						iptablesCommand['-p'][2] = elements.pop(0)
						continue

					if elements[0] == '--dport':
						elements.pop(0)
						iptablesCommand['-p'][3] = elements.pop(0)
						continue

					break

			elif key == '-j':
				targetType = elements.pop(0)
				iptablesCommand['-j'] = self.parseTarget(targetType, elements)

			elif key == '-P':
				iptablesCommand[key] = [elements.pop(0), None]
				iptablesCommand[key][1] = elements.pop(0)

			elif key == '-F':
				if len(elements) > 0 and elements[0][0] != '-':
					iptablesCommand[key] = [elements.pop(0), None]
				else:
					iptablesCommand[key] = [None, None]

			elif key == '-I':
				iptablesCommand[key] = [elements.pop(0), 0]
				if elements[0][0] != '-':
					iptablesCommand[key][1] = int(elements.pop(0))

			else:
				iptablesCommand[key] = [elements.pop(0), nonnegate]
				if len(elements) > 0:
					param = iptablesCommand[key][0]
					if param[-1] == '!':
						iptablesCommand[key][1] = False
						iptablesCommand[key][0] = elements.pop(0)
					else:
						nextToken = elements.pop(0)
						if nextToken[0] != '-':
							iptablesCommand[key][1] = nextToken
						else:
							elements.insert(0, nextToken)

			nonnegate = True

		if iptablesCommand.has_key('-t'):
			table = iptablesCommand['-t'][0]
			del iptablesCommand['-t']
		else:
			table = 'filter'

		self.tables[table].parseIPTablesCommand(iptablesCommand, lineNumber)

	def _buildAllInterfaces(self):

		self.allRulesByInputInterface = {}
		self.allRulesByOutputInterface = {}

		for table in ('filter', 'mangle', 'nat', 'raw'):
			for chain in self.tables[table].chains:
				for rule in self.tables[table].chains[chain].rules:
					if not self.allRulesByInputInterface.has_key(rule.selector.inif[0]):
						self.allRulesByInputInterface[rule.selector.inif[0]] = []
					self.allRulesByInputInterface[rule.selector.inif[0]].append(rule)
					if not self.allRulesByOutputInterface.has_key(rule.selector.outif[0]):
						self.allRulesByOutputInterface[rule.selector.outif[0]] = []
					self.allRulesByOutputInterface[rule.selector.outif[0]].append(rule)

	def getAllInputInterfaces(self):

		self._buildAllInterfaces()
		return self.allRulesByInputInterface

	def getAllOutputInterfaces(self):

		self._buildAllInterfaces()
		return self.allRulesByOutputInterface

	def getAllSelectors(self):

		selectorCount = {}

		for table in ('filter', 'mangle', 'nat', 'raw'):
			for chain in self.tables[table].chains:
				for rule in self.tables[table].chains[chain].rules:
					t = rule.selector.getSelectorTuple()
					if not selectorCount.has_key(t):
						selectorCount[t] = 0
					selectorCount[t] += 1

		return selectorCount

	def getAllSrcAddresses(self):

		sources = set()
		selectorCount = {}

		for table in ('filter', 'mangle', 'nat', 'raw'):
			for chain in self.tables[table].chains:
				for rule in self.tables[table].chains[chain].rules:
					t = tuple(rule.selector.src)
					sources.add(t)
					if not selectorCount.has_key(t):
						selectorCount[t] = 0
					selectorCount[t] += 1

		return sources

	def getAllDstAddresses(self):

		destinations = set()

		for table in ('filter', 'mangle', 'nat', 'raw'):
			for chain in self.tables[table].chains:
				for rule in self.tables[table].chains[chain].rules:
					destinations.add(tuple(rule.selector.dst))

		return destinations

def main(fwFileName):

	firewall = Firewall()

	with open(fwFileName) as f:

		lineNumber = 0
		for line in f.readlines():
			lineNumber += 1
			if line[0] == '#' or line[0] == '\n': continue

			#print "Line {}: parsing rule '{}'".format(lineNumber, line[:-1])
			try:
				firewall.addIPTablesLine(line, lineNumber)
			except Exception as detail:
				print "Error '{}' in line {}".format(detail, lineNumber)
				sys.exit(1)


	## Dump all chains in every table
	#for table in firewall.tables:
	#	print table
	#	for chain in firewall.tables[table].chains:
	#		print "\t", chain

	## Dump all rules from the FORWARD chain filter table
	## include one level of subchains
	for table in firewall.tables:
		print "{}".format(table)
		for chain in firewall.tables[table].builtInChains:
			print "\t{}".format(chain)
			for flattenedRule in firewall.tables[table].getFlattenedRules(chain):
				print "\t\t", flattenedRule
			print

	#print firewall.getAllInputInterfaces().keys()
	#print firewall.getAllOutputInterfaces().keys()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "Usage: {} <file>".format(sys.argv[0])
		sys.exit(1)

	main(sys.argv[1])
