#!/usr/bin/python
#
#
#
#
#
__author__ = 'Jacolon Walker'

import sqlite3 as lite

SQLDB_PATH = "/PATH/To/logsql.sqlite"

class Honeyanalysis(object):

	def __init__(self):
		self.con = lite.connect(SQLDB_PATH)
		self.cur = self.con.cursor()

	def trackConnections(self):
		""" Track connections"""
		# Track all connections from the db and give stats
		total = 0
		ttype = 0
		utype = 0
		otype = 0
		self.cur.execute("SELECT * from connections")
		conns = self.cur.fetchall()
		for num in conns:
			#print type
			if num[2] == "tcp":
				ttype += 1
			elif num[2] == "udp":
				utype += 1
			else:
				otype += 1
			total += + 1

		print "Total # of connections %d" %total
		print "Total # of tcp connections %d" %ttype
		print "Total # of udp connections %d" %utype
		print "Total # of other protocol connections %d" %otype

	def protoStats(self):
		""" Return protocol connections """
		self.cur.execute("select count(connection_protocol) as count, connection_protocol from connections group by connection_protocol order by count desc")
		conns = self.cur.fetchall()
		data = self.parseData(conns)
		return data

	def uniqueIPS(self):
		""" Display unique IPs """
		self.cur.execute("SELECT connections.remote_host FROM connections GROUP BY connections.remote_host")
		conns = self.cur.fetchall()
		data = self.parseData(conns)
		return data

	def downloadsToHash(self):
		""" Display downloads and hashes of the binaries """
		self.cur.execute("select download_url, download_md5_hash from downloads")
		conns = self.cur.fetchall()
		data = self.parseData(conns)
		return data

	def offers(self):
		""" Offers that correlate to downloadstohash """
		self.cur.execute("select * from offers")
		conns = self.cur.fetchall()
		data = self.parseData(conns)
		return data

	def sipVIA(self):
		""" Source IP addrs of SIP connections """
		total = 0
		self.cur.execute("select * from sip_vias")
		conns = self.cur.fetchall()
		data = self.parseData(conns)
		return data

	def parseData(self, data):
		buf = []
		for info in data:
			buf.append(info)
		return buf
