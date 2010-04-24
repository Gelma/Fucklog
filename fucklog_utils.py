#!/usr/bin/env python
# -*- coding: utf-8 -*-

import getopt, sys, socket, dns.resolver, dns.reversename, os
from netaddr import *

#variabili
mysql_host, mysql_user, mysql_passwd, mysql_db = "localhost", "fucklog", "pattinaggio", "fucklog"
geoipdb = "/opt/GeoIP/GeoLiteCity.dat"

def connetto_db():
	import MySQLdb

	try:
		return MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_passwd, db=mysql_db).cursor()
	except:
		logga('MySQL: DB connect fail','exit')

def geoip():
	import pygeoip
	db = connetto_db()
	gip = pygeoip.GeoIP(geoipdb)

	db.execute("select IP, INET_NTOA(IP) from IP where GEOIP is null order by IP")
	for row in db.fetchall():
		try:
			nazione = gip.country_code_by_addr(row[1])
		except:
			nazione = 'N/A'
		try:
			db.execute("update IP set GEOIP=%s where IP=%s", (nazione,row[0]))
		except:
			print "fallito",row
		print row

def update_lasso():
	import urllib

	try:
		lassofile = urllib.urlopen("http://www.spamhaus.org/drop/drop.lasso")
	except:
		print "Lasso update: fallita lettura URL"
		return False

	db = connetto_db()
	db.execute("delete from CIDR where CATEGORY='lasso'")

	for line in lassofile:
		if line.startswith(';'):
			continue
		cidr, note = line[:-1].split(';')
		size = len(IPNetwork(cidr))
		db.execute("insert into CIDR(CIDR, SIZE, NOTE, CATEGORY) values (%s,%s,%s,'lasso')", (cidr.strip(), size, note.strip()))

	if genera_iptables:
		list_cidr('lasso', genera_iptables=True)

def is_already_mapped(IP):
	# prendo un IP, lo confronto con il DB, ritorno vero se conosciuto
	import netaddr

	IP = str(IP)
	db = connetto_db()
	db.execute('select CIDR from CIDR')
	cidrs = []
	cidrs.extend([row[0] for row in db.fetchall()])
	db.close()

	if netaddr.ip.all_matching_cidrs(IP,cidrs):
		return True
	else:
		return False

def ip_to_dns(IP, without_numbers=True):
	# prendo un IP e torno il reverse lookup
	# se without_numbers a True, elimino i numeri

	# tolgo il punto finale dal primo risultato della query
	try:
		complete_name = str(dns.resolver.query(IP.reverse_dns, 'PTR')[0])[:-1]
	except:
		return ""

	if without_numbers:
		return (''.join([letter for letter in complete_name if not letter.isdigit()])).lower()
	else:
		return complete_name

def scanner(IpBase, direction="before", debug=False):
	# Ricevo un IP di partenza (in formato netaddr), una direzione (before/after),
	# un valore di debug (true/false)
	# e torno l'IP piu' lontano (ip_distante), coerente con la partenza per reverse lookup,
	# e la parte comune del reverse lookup,

	# controllo sulla direzione
	if direction != "before" and direction != "after":
		print "direction parameter is wrong"
		return False

	#definisco la partenza
	ip          = IPAddress(str(IpBase))
	ipdns       = ip_to_dns(ip)
	ip_distante = ip

	if is_already_mapped(str(ip)):
		return ip, ipdns

	while True:
		if debug:
			print "--------------------\n"+str(ip)+"\n"+str(ipdns)+"\n"

		# ad ogni inizio di classe controllo di non aver gia' mappato
		if str(ip).endswith('.0'):
			if is_already_mapped(str(ip)):
				break

		if ipdns == ip_to_dns(ip): # da ripristinare
			ip_distante = ip
			if debug:
				print "continuo:", ip, ip_to_dns(ip)
		else:
			if debug:
				print "stoppo:", ip, ip_to_dns(ip)
			break

		if direction == "before":
			ip = ip - 1
		else:
			ip = ip + 1

	return ip_distante, ipdns

def list_cidr(category, genera_iptables=False):
	# ricevo la discriminante category (equivale alla colonna omonima in CIDR db)
	# torno l'elenco, e se iptables è settato feeddo iptables

	import netaddr

	db = connetto_db()
	db.execute("select CIDR from CIDR where CATEGORY=%s", (category,))
	elenco_cidr = []

	for cidr in netaddr.cidr_merge(list([row[0] for row in db.fetchall()])):
		if genera_iptables:
			elenco_cidr.append(str(cidr))
		else:
			print cidr

	if genera_iptables:
		os.system("/sbin/iptables -N fuck-"+category+"-tmp")
		for cidr in elenco_cidr:
			os.system("/sbin/iptables -A fuck-"+category+"-tmp -s "+cidr+" --protocol tcp --dport 25 -j DROP")
		for flag in ['F',  'X']: #chain flush and remove
			os.system("/sbin/iptables -"+flag+" fuck-"+category)
		os.system("/sbin/iptables -E fuck-"+category+"-tmp fuck-"+category)

def suspect_dns_name(dns):
	badwords = ['ip','pool','dhcp','dialup', 'dyn', 'dsl','ppp','dial','cable','retail','3g','static','hsd','umts','wimax','cliente','vfbb']

	if "mail" in dns.lower():
		return False
	for word in badwords:
		if word in dns.lower():
			return True
	return False

def check_ip_brothers(IP):
	ip_to_check = IP
	dns_of_ip   = ip_to_dns(str(IP))

	if is_already_mapped(IP):
		print "Abbandono: IP gia' in lista"
		return None

	if suspect_dns_name(dns_of_ip):
		print "Abbandono: nome non sospetto"
		return None

	ip_inizio = scanner(ip_to_check,direction="before")
	ip_fine   = scanner(ip_to_check,direction="after")

def check_db_ip():
	db = connetto_db()

	db.execute("select IP from IP LIMIT 1")
	for row in db.fetchall():
		IP_base = netaddr.IPAddress(row[0])
		check_ip_brothers(IP_base)

def totali():
	db = connetto_db()
	for A in xrange(255):
		A = str(A)
		ip_begin = A + '.0.0.0'
		ip_end   = A + '.255.255.255'
		db.execute("select count(*) from IP where IP>=INET_ATON(%s) and IP<=INET_ATON(%s)", (ip_begin, ip_end))
		for row in db.fetchall():
			if row[0] != 0:
				print row[0], A

def logga(testo,peso=None):
	print testo
	if peso == "exit":
		sys.exit(-1)
	if peso == "help":
		print """
Opzioni:
	-c --continue     Keep forever
	-d --cidrdsl      Genera elenco DSL da bloccare (sul lavoro di --clusterdsl)
	-e --cidrptr      Genera elenco PTR da bloccare (sul lavoro di clusterptr)
	-f --scanner	  Trova IP vicini (discrimina per reverse lookup)
	-g --geoip        GeoIP localization
	-h --help         Help
	-i --clusterdsl   Scova IP residenziali
	-l --update-lasso Aggiorna elenco di Lasso (Spamhaus)
	-n --clusterptr   Scova IP senza ptr
	-p --iptables     Genera regole per iptables (in unione a opzione -d e -l lasso)
	-t --totali       Totale IP per classi A
"""
		sys.exit(-1)

if __name__ == "__main__":
	azione = None
	genera_iptables = None
	continua = None

	try:
		opts, args = getopt.getopt(sys.argv[1:], "cdefghilnpt", ["continue","cidrdsl","cidrptr","scanner","geoip","help","clusterdsl","update-lasso","clusterptr","iptables","totali"])
	except getopt.GetoptError:
		logga('Main: opzioni invalide: '+sys.argv[1:],'exit')

	for opt, a in opts:
		if opt in ("-h", "--help"):
			logga('','help')
		elif opt in ('-g', "--geoip"):
			azione = "geoip"
		elif opt == '-c':
			continua == 1
		elif opt in ('-t', '--totali'):
			azione = "totali"
		elif opt in ('-i', '--clusterdsl'):
			azione = "clusterdsl"
		elif opt in ('-d', '--cidrdsl'):
			azione = "cidrdsl"
		elif opt in ('-e', '--cidrptr'):
			azione = "cidrptr"
		elif opt in ('-p', '--iptables'):
			genera_iptables = 1
		elif opt in ('-n', '--clusterptr'):
			azione = "clusterptr"
		elif opt in ('-f', '--scanner'):
			azione = 'scanner'
		elif opt in ('-l', '--update-lasso'):
			azione = 'update_lasso'

	if len(opts) == 0:
		logga('', 'help')

	if azione == "geoip":
		geoip()
	if azione == "totali":
		totali()
	if azione == "clusterdsl":
		clusterdsl()
	if azione == "cidrdsl":
		cidrdsl()
	if azione == "clusterptr":
		clusterptr()
	if azione == "cidrptr":
		cidrptr()
	if azione == "scanner":
		scanner()
	if azione == "update_lasso":
		update_lasso()