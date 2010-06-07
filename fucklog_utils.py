#!/usr/bin/env python
# -*- coding: utf-8 -*-
# http://code.google.com/p/netaddr
# python-dnspython

import netaddr, os, sys, socket, time, datetime, re, thread

if True:
	# Dati costanti
	# MysqlDB
	mysql_host, mysql_user, mysql_passwd, mysql_db = "localhost", "fucklog", "pattinaggio", "fucklog"
	# GeoIP
	geoip_db_file = "/opt/GeoIP/GeoLiteCity.dat"
	geoip_db = False
	# Flags opzioni
	azione = None
	Genera_Iptables = None
	KeepAlive = False
	Cached_CIDRs = None
	# Locks
	lock_cached_cidrs = thread.allocate_lock()

# funzioni ausiliarie
def connetto_db():
	import MySQLdb
	try:
		return MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_passwd, db=mysql_db).cursor()
	except:
		logga('MySQL: Connessione al DB fallita','exit')

def compatta_cbl():
	# leggo /tmp/cbl e compatto in cidr ogni IP per riga
	f = open('/tmp/cbl','r')

	elencone = list([l[:-1] for l in f])
	cidr = []

	print len(elencone)

	while elencone:
		print "botta"
		for ip in elencone[:10000]:
			cidr.append(ip)
		cidr = netaddr.cidr_merge(cidr)
		print cidr
		elencone = elencone[10000:]

def geoip_from_ip(IP):
	# ricevo un IP, torno la nazione o None
	import pygeoip
	global geoip_db

	if geoip_db is False:
		geoip_db = pygeoip.GeoIP(geoip_db_file)
	try:
		return geoip_db.country_name_by_addr(IP)
	except:
		return None

def get_cidr(category):
	# ricevo la discriminante category (equivale alla colonna omonima in CIDR db)
	# torno la lista delle cidr, e se Genera_Iptables è settato feeddo iptables

	elenco_cidr = []
	db = connetto_db()
	db.execute("select CIDR from CIDR where CATEGORY=%s order by SIZE desc", (category,))

	for cidr in netaddr.cidr_merge(list([row[0] for row in db.fetchall()])):
			elenco_cidr.append(str(cidr))

	if Genera_Iptables:
		os.system("/sbin/iptables -N fuck-"+category+"-tmp")
		for cidr in elenco_cidr:
			os.system("/sbin/iptables -A fuck-"+category+"-tmp -s "+cidr+" --protocol tcp --dport 25 -j DROP")
		for flag in ['F',  'X']: #chain flush and remove
			os.system("/sbin/iptables -"+flag+" fuck-"+category)
		os.system("/sbin/iptables -E fuck-"+category+"-tmp fuck-"+category)

	return elenco_cidr

def reverse_ip(IP):
	# ricevo un IP 1.2.3.4 e lo torno girato 4.3.2.1

	IP = IP.split('.')
	IP.reverse()
	return '.'.join(IP)

def is_pbl(IP):
	# ricevo un IP. Torno False se non in pbl.spamhaus.org
	# torno il link diversamente

	import dns.resolver, dns.reversename
	
	qstr = "%s.pbl.spamhaus.org." % reverse_ip(IP)
	try:
		qa = dns.resolver.query(qstr, 'TXT')
	except dns.exception.DNSException:
		return False
	for rr in qa:
		for s in rr.strings:
			return s

def iptables_to_nat():
	# prendo tutti gli IP bloccati da fucklog e li metto nel nat per la redirezione della 25 verso la 25000
	# smtp-sink -4 -c -d "%Y%m%d%H%M." -u check -R /home/gelma.net/check/SpoolSpam/new/ -h lugbs.linux.it 25000 512
	# iptables -t nat -F

	file_per_iptables = "/tmp/.fucklog_iptables_restore"

	while True:
		# creo la testa del file da passare a iptables-restore
		filettone = open(file_per_iptables, 'w')
		filettone.write("*nat"+"\n")
		filettone.write(":PREROUTING ACCEPT [0:0]"+"\n")
		filettone.write(":OUTPUT ACCEPT [0:0]"+"\n")
		filettone.write(":POSTROUTING ACCEPT [0:0]"+"\n")
	
		# le regole effettive
		for ip in os.popen("/sbin/iptables-save |/bin/grep '^-A fucklog-.*-p tcp -m tcp --dport 25 -m time --datestop.*-j DROP' | cut -f 4 -d ' '"):
			ip = ip[:-1]
			filettone.write("-A PREROUTING -s "+ip+" -p tcp -m tcp --dport 25 -j REDIRECT --to-ports 25000"+"\n")
		
		# la coda e chiudo
		filettone.write("COMMIT"+"\n")
		filettone.close()
		
		# invoco iptables-restore
		os.popen("/sbin/iptables-restore < " + file_per_iptables)
		os.remove(file_per_iptables)
		
		if KeepAlive is False:
			break
		else:
			time.sleep(3600)
	
def nmap_fingerprint(IP):
	# dato un IP, me lo spupazzo con nmap per trovare l'OS fingerprint
	# ritorno le righe significative di testo di nmap

	import os, netaddr
	
	client_da_usare      = '/opt/nmap/bin/nmap '			# ocio al blank finale
	argomenti_del_client = '-O --osscan-limit -F --fuzzy '	# ocio al blank finale
	responso = []
	
	# validazione IP	
	try:
		IP=netaddr.IPAddress(IP)
	except:
		return False
	
	for line in os.popen(client_da_usare+argomenti_del_client+str(IP)):
		if line.startswith( ('Running', 'Aggressive', 'Device', 'OS deta') ):
			responso.append(line)

	if len(responso):
		return ''.join(responso)
	else:
		return None

def update_OS_worker(IP,date_from_db):
	# ricevo un IP, lo nmappo metto i dati in OS->IP->FUCKLOG->MYSQL
	# date_from_db è data e ora dell'update dell'IP. Lo re-inserisco per non perdere l'informazione con l'inserimento del testo nmap
	
	import time
	
	db = connetto_db()
	print IP
	
	os_finger = nmap_fingerprint(IP)
	if not os_finger:
		os_finger = 'N/A'

	try:
		db.execute("UPDATE IP set OS=%s, DATE=%s where IP=INET_ATON(%s)", (os_finger, date_from_db, IP))
	except:
		print IP,"fallito update db"
	
	db.close()

# funzioni richiamabili da riga di comando

def Update_OS():
	# aggiorno OS->IP->FUCKLOG->MYSQL
	# prendo gli IP piu' recenti, sfrutto nmap, cerco di individuarne il Sistema Operativo
	
	import time, threading
	
	Ip_in_parallelo = 30
	db = connetto_db()
	
	while True:
		coda_threads = []
		db.execute("select INET_NTOA(IP), DATE from IP where OS is NULL order by DATE desc limit "+str(Ip_in_parallelo))
		for row in db.fetchall():
			try:
				IP = netaddr.IPAddress(row[0])
			except:
				continue
			coda_threads.append( threading.Thread(None,update_OS_worker,None,(IP, row[1])) )
			coda_threads[-1].start()
		
		# attendo l'uscita di ogni thread
		for threddone in coda_threads:
			try: # potrei avere un eccezione nel caso terminasse il thread prima del join
				threddone.join()
			except:
				pass
		
		print "Mi puoi killare"
		time.sleep(60)

	db.close()

def Cristini():
	# leggo il file di Necro

	db = connetto_db()
	filettone = open('/tmp/necro','r')

	for line in filettone:
		if line.startswith('#'): continue
		line = line[:-1].split()
		PBL = line[0]
		CIDR = netaddr.IPNetwork(line[1])

		try:
			db.execute("delete from CIDR where CIDR=%s", (str(CIDR),))
			db.execute("insert into CIDR (CIDR, NAME, SIZE, CATEGORY) values (%s,%s,%s,'pbl')", (str(CIDR), PBL, CIDR.size))
		except:
			print "Errore:",CIDR

def Size_cidr(cidr):
	# Dato un Network CIDR torno il numero di IP che lo compongono

	try:
		return netaddr.IPNetwork(cidr).size
	except:
		return None

def Cidr_db_size():
	# Aggiorno SIZE->CIDR->FUCKLOG->MYSQL

	while True:
		db = connetto_db()
		db.execute("select CIDR from CIDR where SIZE is null")
		for row in db.fetchall():
			size = Size_cidr(row[0])
			try:
				db.execute("update CIDR set SIZE=%s where CIDR=%s", (size, row[0]))
			except:
				print "fallito inserimento", row[0]

		db.execute("select SUM(SIZE) from CIDR")
		for row in db.fetchall():
			print "Totale IP in CIDR:",row[0]

		db.close()
		if KeepAlive is False:
			break
		else:
			time.sleep(3600)

def Geoloc_update():
	# Aggiorno le tuple Null in GEOIP->IP->FUCKLOG->MYSQL
	# onoro KeepAlive

	while True:
		db = connetto_db()
		db.execute("select IP from IP where GEOIP is null")
		for row in db.fetchall():
			ip      = netaddr.IPAddress(row[0])
			nazione = geoip_from_ip(str(ip))
			try:
				db.execute("update IP set GEOIP=%s where IP=%s", (nazione, int(ip)))
			except:
				print "fallito",str(ip),nazione
			print ip, nazione
		db.close()
		if KeepAlive is False:
			break
		else:
			time.sleep(3600)

def Pbl_in_iptables():
	# Scanno gli IP in Iptables e torno i link a PBL (i primi 20)

	counter = 0
	for chain in os.popen('/sbin/iptables -L -n|grep -i fucklog|tac'):
		for ip in os.popen('/sbin/iptables -L '+chain.split()[1]+' -n | /bin/grep DROP'):
			ip = ip.split()[3]
			if is_already_mapped(ip): continue
			res = is_pbl(ip)
			if res:
				print res
				counter = counter +1
				if counter == 20:
					return

def Pbl_queue():
	# Prendo le pbl.spamhaus.org dal log di postfix
	# Porto il tutto in PBLURL->Fucklog-Mysql
	# Vaglio le CIDR inserite via WEB

	global Genera_Iptables
	global Cached_CIDRs
	Cached_CIDRs = None # Azzero la cache delle CIDRs

	db = connetto_db()
	regexp = re.compile('.*blocked using pbl.spamhaus.org;.*bl\?ip=(.*);')
	grep_command = "/bin/grep --mmap pbl.spamhaus.org /var/log/everything/current"

	while True:
		# prendo i pbl dai log e li porto in tabella
		for log_line in os.popen(grep_command):
			m = regexp.match(log_line) # match for regexp
			if m: # if it matches
				ip = m.group(1)
				if not is_already_mapped(ip):
					try:
						db.execute("insert into PBLURL (URL) values (%s)", (ip,))
						print "Metto in coda web:",ip
					except:
						pass

		# prendo le CIDR inserite via web e le vaglio
		db.execute("select URL, CIDR from PBLURL where CIDR is NOT null")
		for row in db.fetchall():
			IP = row[0]
			CIDR = row[1]

			# controllo la validita' dei dati
			try:
				tmp = netaddr.IPAddress(IP)
			except:
				print "Non è un IP valido", IP
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue
			try:
				tmp = netaddr.IPNetwork(CIDR)
			except:
				print "Non è una CIDR valida", CIDR
				db.execute("delete from PBLURL where URL=%s",(IP,))

			# controllo che non sia gia' mappato (solo la roba nuova)
			if is_already_mapped(IP):
				print "Gia' mappato",IP
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue

			# controllo che IP e CIDR siano compatibili
			if not netaddr.ip.all_matching_cidrs(netaddr.IPAddress(IP),[netaddr.IPNetwork(CIDR),]):
				print "Non combaciano IP/CIDR",IP,CIDR
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue

			# inserisco e cancello
			try:
				db.execute("insert into CIDR(CIDR, SIZE, CATEGORY) values (%s,%s,'pbl')", (CIDR.strip(), Size_cidr(CIDR)))
			except:
				print "Fallito inserimento in CIDR di", IP, CIDR
				db.execute("delete from PBLURL where URL=%s",(IP,))

			print "Inserito in CIDR: ",IP,CIDR
			Cached_CIDRs = None

		# ripeto il controllo su tutti gli IP rimasti
		db.execute("select URL from PBLURL where CIDR is null")
		for row in db.fetchall():
			IP = row[0]
			# controllo la validita' dei dati
			try:
				tmp = netaddr.IPAddress(IP)
			except:
				print "Non è un IP valido", IP
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue
			# controllo che non sia gia' mappato
			if is_already_mapped(IP):
				print "Gia' mappato (tutti)",IP
				db.execute("delete from PBLURL where URL=%s",(IP,))

		if Genera_Iptables:
			print "Genero Iptables"
			get_cidr('pbl')

		# controllo il ciclo
		if KeepAlive is False:
			break
		else:
			time.sleep(3600)

def Lasso_update():
	# Invocato, scarico e aggiorno l'elenco di Spamhaus Lasso.
	# Onoro --iptables e --keep
	import urllib

	while True:
		print "Update:",str(datetime.datetime.now())
		try:
			lassofile = urllib.urlopen("http://www.spamhaus.org/drop/drop.lasso")
		except:
			logga("Lasso update: fallita lettura URL")
			time.sleep(86400)
			continue

		db = connetto_db()
		db.execute("delete from CIDR where CATEGORY='lasso'")

		for line in lassofile:
			if line.startswith(';'):
				continue
			cidr, note = line[:-1].split(';')
			db.execute("insert into CIDR(CIDR, SIZE, NAME, CATEGORY) values (%s,%s,%s,'lasso')", (cidr.strip(), Size_cidr(cidr), note.strip()))

		if Genera_Iptables:
			get_cidr('lasso')

		if KeepAlive is False:
			break
		else:
			time.sleep(129600) # aggiorna dopo 36 ore

def UCE_update():
	# Invocato, scarico e aggiorno l'elenco di UCE.
	# Onoro KeepAlive

	while True:
		print "UCE update:",str(datetime.datetime.now())

		os.system('/usr/bin/rsync -aPz --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-2.uceprotect.net /tmp/.dnsbl-2.uceprotect.net')
		os.system('/usr/bin/rsync -aPz --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-3.uceprotect.net /tmp/.dnsbl-3.uceprotect.net')
		
		db = connetto_db()
		db.execute("delete from CIDR where CATEGORY='uce'")

		for cidr in os.popen("/bin/cat /tmp/.dnsbl-?.uceprotect.net"):
			cidr = cidr.split()[0]
			try:
				cidr = netaddr.IPNetwork(cidr)
			except:
				#print "Scarto cidr",cidr
				continue
			try:
				db.execute("insert into CIDR(CIDR, SIZE, CATEGORY) values (%s,%s,'uce')", (cidr, cidr.size))
			except:
				pass
				#print "Fallito inserimento", cidr

		if KeepAlive is False:
			break
		else:
			time.sleep(86400) # aggiorna dopo 36 ore

def Totali():
	# Invocato torno il numero totale di IP suddivisi per classi A

	db = connetto_db()
	for A in xrange(255):
		A = str(A)
		ip_begin = A + '.0.0.0'
		ip_end   = A + '.255.255.255'
		db.execute("select count(*) from IP where IP>=INET_ATON(%s) and IP<=INET_ATON(%s)", (ip_begin, ip_end))
		for row in db.fetchall():
			if row[0] != 0:
				print row[0], A

def Clean_ip():
	# Passo in rassegna gli IP in IP->Fucklog->MySQL e levo quelli gia' in CIDR

	db = connetto_db()
	db.execute("select IP from IP order by IP")
	for row in db.fetchall():
		IP = netaddr.IPAddress(row[0])
		if is_already_mapped(str(IP)):
			print "Elimino: ",IP
			db.execute("delete from IP where IP=%s",(int(IP),))

def is_already_mapped(IP,reset_cache=False,torna_la_cidr=False):
	# prendo un IP, lo confronto con il DB, ritorno vero se conosciuto
	# utilizzo cached_cidr a livello globale
	# reset_cache = forza il flush della cache
	# torna_la_cidr = ritorna la classe invece del semplice True

	global Cached_CIDRs

	if Cached_CIDRs is None or reset_cache is True:
		lock_cached_cidrs.acquire()
		# inizializzo il dizionario
		Cached_CIDRs = {}
		for n in xrange(256):
			Cached_CIDRs[str(n)] = []
		# succhio dal db e creo le liste per classe A
		db = connetto_db()
		db.execute('select CIDR from CIDR order by SIZE desc')
		for row in db.fetchall():
			CIDR = row[0]
			classe = CIDR.split('.')[0]
			Cached_CIDRs[classe].append(CIDR)
		# riduco ogni classe A ai minimi termini
		for A in Cached_CIDRs:
			if len(Cached_CIDRs[A]):
				#inizio = len(Cached_CIDRs[A])
				Cached_CIDRs[A] = netaddr.cidr_merge(Cached_CIDRs[A])
				#print "Differenza",inizio-len(Cached_CIDRs[A])
		db.close()
		lock_cached_cidrs.release()

	ip = netaddr.IPAddress(str(IP).strip())
	ClasseA = str(IP).split('.')[0]
	ClassePrecedente = str(int(ClasseA) - 1)

	for CIDR in Cached_CIDRs[ClasseA] + Cached_CIDRs[ClassePrecedente]:
		if netaddr.ip.all_matching_cidrs(ip,[CIDR,]):
			if torna_la_cidr:
				return str(netaddr.ip.all_matching_cidrs(ip,[CIDR,])[0])
			else:
				return True
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
	ip          = netaddr.IPAddress(str(IpBase))
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

	ip_inizio, dns_inizio = scanner(ip_to_check,direction="before")
	ip_fine,   dns_fine   = scanner(ip_to_check,direction="after")

	print "risultato:",ip_inizio,ip_fine

def check_db_ip():
	db = connetto_db()

	db.execute("select IP from IP order by RAND() LIMIT 1")
	for row in db.fetchall():
		IP_base = netaddr.IPAddress(row[0])
		check_ip_brothers(IP_base)

def logga(testo,peso=None):
	if testo != '':
		print testo
	if peso == "exit":
		sys.exit(-1)
	if peso == "help":
		print """
Opzioni:
	-c --cristini        Flusso di necro (da stdin)
	-f --scanner	     *Trova IP vicini (discrimina per reverse lookup)
	-g --geoloc-update   Aggiorna la geolocalizzazione in MySQL (capisce -k)
	-h --help            *Help
	-i --iptables-update (flag) Genera regole per iptables (onora -d -l)
	-k --keepalive       (flag) Imposta la ripetizione perpetua della funzione
	-l --lasso-update    Aggiorna la lista Lasso di Spamhaus (onora -i -k)
	-n --clusterptr      *Scova IP senza ptr
	-p --pbl-in-iptables Torna le PBL attive presenti negli IP bloccati da iptables
	-s --size_cidr       Torna il numero di IP che compongono una CIDR
	-t --totali          Totale degli IP suddivisi per classi A
	-x --cidr_db_size    Aggiorna le dimensioni delle CIDR in MySQLdb
	-y --pbl-queue       Porta pbl URL da log nella tabella PBLURL, e committo le CIDR inserite via web (onoro -k e -i)
	-z --clean-ip        Sego da IP->MySQL gli IP presenti nelle CIDR pbl
"""
		sys.exit(-1)

if __name__ == "__main__":
	import getopt
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "cfghiklnpstxyz", ["cristini","scanner","geoloc-update","help","iptables-update","keepalive","lasso-update","clusterptr","pbl-in-iptables","size-cidr","totali","cidr_db_size","pbl-queue","clean-ip"])
	except getopt.GetoptError:
		logga('Main: opzioni non valide: '+sys.argv[1:],'exit')

	for opt, a in opts:
		if opt in ('-c', "--cristini"):
			azione = "cristini"
		elif opt in ('-g', "--geoloc-update"):
			azione = "geoloc-update"
		elif opt in ("-h", "--help"):
			logga('','help')
		elif opt in ('-i', '--iptables-update'):
			Genera_Iptables = 1
		elif opt in ("-k", "--keepalive"):
			KeepAlive = True
		elif opt in ('-l', '--lasso-update'):
			azione = 'lasso-update'
		elif opt in ('-p', '--pbl-in-iptables'):
			azione = 'pbl-in-iptables'
		elif opt in ('-s', '--size-cidr'):
			azione = 'size_cidr'
		elif opt in ('-t', '--totali'):
			azione = "totali"
		elif opt in ('-x', '--cidr_db_size'):
			azione = "cidr_db_size"
		elif opt in ('-y', '--pbl-queue'):
			azione = "pbl-queue"
		# ordered
		elif opt in ('-n', '--clusterptr'):
			azione = "clusterptr"
		elif opt in ('-f', '--scanner'):
			azione = 'scanner'
		elif opt in ('-z', '--clean-ip'):
			azione = 'clean-ip'

	if len(opts) == 0:
		logga('', 'help')

	if azione == "cristini":
		Cristini()
	elif azione == "cidr_db_size":
		Cidr_db_size()
	elif azione == "geoloc-update":
		Geoloc_update()
	elif azione == "lasso-update":
		Lasso_update()
	elif azione == "pbl-in-iptables":
		Pbl_in_iptables()
	elif azione == "size-cidr":
		Size_cidr()
	elif azione == "totali":
		Totali()
	elif azione == "clusterptr":
		clusterptr()
	elif azione == "scanner":
		scanner()
	elif azione == "pbl-queue":
		Pbl_queue()
	elif azione == "clean-ip":
		Clean_ip()