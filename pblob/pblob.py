#!/usr/bin/python
import urllib2
import re
import socket
import time

socket.setdefaulttimeout(60) # Set timeout connection for urllib2

class sphPBL:
	"""Give me an IP, I'll give you back its complete Spamhaus PBL cidr"""

	ip = None
	pbl_num = None
	pbl_url = None
	cidr = None

	_header = {"User-Agent": "Opera/9.80 (X11; Linux i686; U; it) Presto/2.9.168 Version/11.50",
			   "Accept": "text/html"}

	def __init__(self,ip=None):
		if (ip != None):
			self.populate(ip)

	def populate(self,ip):
		self.ip = ip
		self._fetch_pbl()
		self._fetch_cidr()
		return 0

	def _read_webpage(self, req):
		while True:
			try:
				return urllib2.urlopen(req).read()
				break
			except:
				print "Failed SpamHaus request. Retry in 2 minutes."
				time.sleep(120)

	def _fetch_pbl(self):
		if (self.ip == None):
			return 1
		req_url = "http://www.spamhaus.org/query/bl?ip=%s" % self.ip
		req = urllib2.Request(req_url,None,self._header)
		page = self._read_webpage(req)
		reg = re.compile('<LI><a href="([^"]+)">PBL([0-9]+)</a><br>')
		m = re.findall(reg, page)
		if (m != []):
			self.pbl_url = m[0][0]
			self.pbl_num = m[0][1]
		return 0

	def _fetch_cidr(self):
		if (self.pbl_url == None):
			return 1
		req = urllib2.Request(self.pbl_url,None,self._header)
		page = self._read_webpage(req)
		reg = re.compile('<font color="red">([^<]+)</font> is listed on the Policy Block List \(PBL\)</span><br>')
		m = re.findall(reg, page)
		if (m != []):
			self.cidr = m[0]
		return 0
