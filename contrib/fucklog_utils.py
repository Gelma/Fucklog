#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Questo file ha, grosso modo perso, ogni sua utilita'. Viene lasciato in giro semplicemente perché sono ancora
# da migrare alcune parti di codice.

import netaddr, os, sys, socket, time, datetime, re, thread

if True:
	# Dati costanti
	# Flags opzioni
	azione = None
	Genera_Iptables = None
	KeepAlive = False
	Cached_CIDRs = None
	# Locks
	lock_cached_cidrs = thread.allocate_lock()

def iptables_to_nat():
	# prendo tutti gli IP bloccati da fucklog e li metto nel nat per la redirezione della 25 verso la 25000
	# smtp-sink -4 -c -d "%Y%m%d%H%M." -u check -R /home/gelma.net/check/SpoolSpam/new/ -h li61-168.members.linode.com. 25000 512
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
	
	client_da_usare      = 'nice -n20 /opt/nmap/bin/nmap '			# ocio al blank finale
	argomenti_del_client = '-O --osscan-limit -F --fuzzy '	# ocio al blank finale
	responso = []
	
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
	
def Update_OS():
	# aggiorno OS->IP->FUCKLOG->MYSQL
	# prendo gli IP piu' recenti, sfrutto nmap, cerco di individuarne il Sistema Operativo
		
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
		time.sleep(1800)

	db.close()

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
	-f --scanner	     *Trova IP vicini (discrimina per reverse lookup)
	-g --geoloc-update   Aggiorna la geolocalizzazione in MySQL (capisce -k)
	-h --help            *Help
	-i --iptables-update (flag) Genera regole per iptables (onora -d -l)
	-k --keepalive       (flag) Imposta la ripetizione perpetua della funzione
	-n --clusterptr      *Scova IP senza ptr
	-p --pbl-in-iptables Torna le PBL attive presenti negli IP bloccati da iptables
	-s --size_cidr       Torna il numero di IP che compongono una CIDR
	-t --totali          Totale degli IP suddivisi per classi A
	-x --cidr_db_size    Aggiorna le dimensioni delle CIDR in MySQLdb
	-z --clean-ip        Sego da IP->MySQL gli IP presenti nelle CIDR pbl
"""
		sys.exit(-1)

if __name__ == "__main__":
	import getopt
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "fghiknpstxz", ["scanner","geoloc-update","help","iptables-update","keepalive","clusterptr","pbl-in-iptables","size-cidr","totali","cidr_db_size","clean-ip"])
	except getopt.GetoptError:
		logga('Main: opzioni non valide: '+sys.argv[1:],'exit')

	for opt, a in opts:
		if opt in ('-g', "--geoloc-update"):
			azione = "geoloc-update"
		elif opt in ("-h", "--help"):
			logga('','help')
		elif opt in ('-i', '--iptables-update'):
			Genera_Iptables = 1
		elif opt in ("-k", "--keepalive"):
			KeepAlive = True
		elif opt in ('-p', '--pbl-in-iptables'):
			azione = 'pbl-in-iptables'
		elif opt in ('-s', '--size-cidr'):
			azione = 'size_cidr'
		elif opt in ('-t', '--totali'):
			azione = "totali"
		elif opt in ('-x', '--cidr_db_size'):
			azione = "cidr_db_size"
		# ordered
		elif opt in ('-n', '--clusterptr'):
			azione = "clusterptr"
		elif opt in ('-f', '--scanner'):
			azione = 'scanner'
		elif opt in ('-z', '--clean-ip'):
			azione = 'clean-ip'

	if len(opts) == 0:
		logga('', 'help')

	if azione == "cidr_db_size":
		Cidr_db_size()
	elif azione == "geoloc-update":
		Geoloc_update()
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
	elif azione == "clean-ip":
		Clean_ip()
