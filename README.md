Framework for checking IPTables rules for correctness and soundness.

Still an early work but it can already catch some errors:

1. Contradicting rules in chains and subchains
2. Indentical rules in chains
3. Overlapping rules

Input has to be in a form of a series of iptables commands.

This is _very alpha state software_!!!!

Some TODO items:

1. It would be much better to use parsers from iptables codebase

2. Parsing iptables-save output as well as XML

3. Modularizing checks, so that they can be easily added

4. Better design and architecture, more in line with Python

5. More Pythonesque code :) 

As for the last two points, I would very gladly hear comments
from Python experts!
