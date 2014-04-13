#!/usr/bin/python
from dsm import *

def hline():
	print "-" * 30

hline()
d = Honeyanalysis()
conns = d.trackConnections()
hline()
pstats = d.protoStats()
print "Count\t", "Protocol"
hline()
for item in pstats:
	print item[0], "\t|", item[1]
hline()
print "Malware downloads - hashes"
bd = d.offers()
hashes = d.downloadsToHash()
for url,hash in zip(bd,hashes):
	print url[2], "-", hash[1]
hline()
