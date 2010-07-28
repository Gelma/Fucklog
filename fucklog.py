#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, fucklog_utils, MySQLdb, netaddr, os, re, shelve, sys, thread, threading, time

if True: # definizione variabili globali
	mysql_host, mysql_user, mysql_passwd, mysql_db = "localhost", "fucklog", "pattinaggio", "fucklog"
	interval = 10 # minutes
	RegExps = [] # list of regular expressions to apply
	RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # blacklist
	RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
	list_of_iptables_chains = {}
	postfix_log_file = "/var/log/everything/current"
	# Statistics
	today_ip_blocked = all_ip_blocked = 0
	# Locks
	lock_output_log_file = thread.allocate_lock()
	lock_stats_update    = thread.allocate_lock()
	lock_aggiorna_cidrarc= thread.allocate_lock()
	# GeoIP
	geoip_db_file = "/opt/GeoIP/GeoLiteCity.dat"
	geoip_db = False
	# Logfile
	output_log_file = '/tmp/.fucklog_log_file.txt'
	log_file = open(output_log_file,'a')
	# MRTG files
	file_mrtg_stats = open("/tmp/.fucklog_mrtg", 'w')

def aggiorna_cidrarc(Id=1):
	"""Prendo il contenuto di Cidr->Fucklog->MySQL e ottimizzo, infilando il risultato in CidrArc->Fucklog-MySQL"""
	
	if lock_aggiorna_cidrarc:
		return
	
	lock_aggiorna_cidrarc.acquire()
	logit('AggCidrarc: inizio')
	cronometro = time.time()
	db = connetto_db()
	db.execute('select CIDR from CIDR')
	lista_cidrs_nuovi = set([c[0] for c in db.fetchall()])
	logit('AggCidrarc: totale CIDR iniziali '+str(len(lista_cidrs_nuovi)))
	lista_cidrs_nuovi = set(netaddr.cidr_merge(lista_cidrs_nuovi))
	logit('AggCidrarc: totale CIDR finali '+str(len(lista_cidrs_nuovi)))
	
	db.execute('select CIDR from CIDRARC')
	lista_cidrs_vecchi = set([netaddr.IPNetwork(c[0]) for c in db.fetchall()])
			
	for cidr in lista_cidrs_nuovi: # solo in nuovi, aggiungo
		if cidr not in lista_cidrs_vecchi:
			logit('AggCidrarc: aggiungo '+cidr)
			cidr = netaddr.IPNetwork(cidr)
			db.execute('insert into CIDRARC (CIDR, IPSTART, IPEND, SIZE) values (%s, %s, %s, %s)', (cidr, int(cidr[0]), int(cidr[-1]), cidr.size))

	for cidr in lista_cidrs_vecchi: # solo in vecchi, cancello
		if cidr not in lista_cidrs_nuovi:
			logit('AggCidrarc: rimuovo '+cidr)
			db.execute('delete from CIDRARC where CIDR=%s', (cidr,))

	db.close()
	logit('AggCidrarc: completato in '+str(time.time() - cronometro)+' secondi')
	lock_aggiorna_cidrarc.release()
	
def aggiorna_lasso(Id):
	"""Prelevo la lista Lasso e aggiorno Cidr->Fucklog->Mysql"""
	
	import urllib
	
	while True:
		time.sleep(129600) # aggiorna dopo 36 ore
		logit('Lasso: aggiornamento '+str(datetime.datetime.now()))
		try:
			lassofile = urllib.urlopen("http://www.spamhaus.org/drop/drop.lasso")
		except:
			logit("Lasso: aggiornamento fallito")
			time.sleep(3600)
			continue

		db = connetto_db()
		db.execute("delete from CIDR where CATEGORY='lasso'")

		for line in lassofile:
			if line.startswith(';'):
				continue
			cidr, note = line[:-1].split(';')
			try:
				cidr = netaddr.IPNetwork(cidr)
			except:
				logit('Lasso: errore con '+cidr)
				continue
			try:
				db.execute("insert into CIDR (CIDR, SIZE, NAME, CATEGORY) values (%s,%s,%s,'lasso')", (cidr, cidr.size, note.strip()))
			except:
				logit('Lasso: errore db con '+cidr)
		del lassofile

		db.close()
		aggiorna_cidrarc()

def aggiorna_uce(Id):
	"""Aggiorno la lista UCE2 in Cidr->Fucklog->MySQL"""
	
	while True:
		time.sleep(90000) # aggiorna ogni 25 ore
		logit('UCE: aggiornamento '+str(datetime.datetime.now()))

		os.system('/usr/bin/rsync -aqz --no-motd --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-2.uceprotect.net /tmp/.dnsbl-2.uceprotect.net')
		#variante con UCE3: os.system('/usr/bin/rsync -aPz --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-3.uceprotect.net /tmp/.dnsbl-3.uceprotect.net')
		
		db = connetto_db()
		db.execute("delete from CIDR where CATEGORY='uce'")

		for line in os.popen("/bin/cat /tmp/.dnsbl-?.uceprotect.net"):
			if line.startswith('#') or line.startswith('$') or line.startswith('$') or line.startswith(':') or line.startswith('!') or line.startswith('127.0.0.2  Test Record'):
				continue
			note = line.split('because')[1].split('are hosted')[0].strip()
			cidr = line.split()[0]
			try:
				cidr = netaddr.IPNetwork(cidr)
			except:
				logit('UCE: errore con '+cidr)
				continue
			try:
				db.execute("insert into CIDR(CIDR, NAME, SIZE, CATEGORY) values (%s,%s,%s,'uce')", (cidr, note, cidr.size))
			except:
				logit('UCE: errore db con '+line)
		
		db.close()
		aggiorna_cidrarc()

def aggiorna_pbl(Id):
	"""Controllo le CIDR di PBL inserite via web e le attivo (PblUrl->Fucklog->MySQL)"""

	while True:
		logit('WebPBL: inizio')
		db = connetto_db()
		db.execute("select URL, CIDR from PBLURL where CIDR is NOT null") # Prelevo le CIDR inserite via Web
		for row in db.fetchall():
			IP = row[0]
			CIDR = row[1]

			try: # controllo la validita' dei dati
				tmp = netaddr.IPAddress(IP)
			except:
				logit('WebPBL: IP non valido '+IP)
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue
			try:
				CIDR = netaddr.IPNetwork(CIDR)
			except:
				logit("WebPBL: CIDR non valida "+CIDR)
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue

			if ip_gia_in_cidr(IP):
				logit("WebPBL: gia' mappato "+IP)
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue

			if not netaddr.ip.all_matching_cidrs(netaddr.IPAddress(IP),[netaddr.IPNetwork(CIDR),]):
				logit("WebPBL: IP/CIDR non combaciano "+str(IP)+" "+str(CIDR))
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue

			try: # tutto ok, quindi inserisco
				db.execute("insert into CIDR (CIDR, SIZE, CATEGORY) values (%s,%s,'pbl')", (CIDR, CIDR.size))
				aggiorna_cidrarc()
			except:
				logit("WebPBL: fallito inserimento "+CIDR)
			db.execute("delete from PBLURL where URL=%s",(IP,))
			
		
		# ripeto il controllo su tutti gli IP rimasti
		db.execute("select URL from PBLURL where CIDR is null")
		for row in db.fetchall():
			IP = row[0]
			try:
				tmp = netaddr.IPAddress(IP)
			except:
				logit('WebPBL: non è un IP valido '+IP)
				db.execute("delete from PBLURL where URL=%s",(IP,))
				continue
			if ip_gia_in_cidr(IP):
				logit("WebPBL: gia' mappato "+IP)
				db.execute("delete from PBLURL where URL=%s",(IP,))

		db.close()
		time.sleep(3600)

def connetto_db():
	"""Torno una connessione al DB MySQL"""
	
	try:
		return MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_passwd, db=mysql_db).cursor()
	except:
		logit('Connetto_db: errore nella connesione')
		sys.exit(-1)

def rimozione_ip_vecchi(Id):
	"""Leggo Ip->Fucklog->MySQL e rimuovo gli IP che da più di 4 mesi non spammano (ripeto ogni 8 ore)"""
	
	while True:
		time.sleep(28800)
		logit('RimozioneIP: inizio')
		db = connetto_db()
		db.execute('delete from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 4 MONTH)')
		db.close()
	
def pbl_expire(Id):
	"""Controllo tutte le CIDR PBL più vecchie di due mesi, ed eventualmente le sego (Cidr->Fucklog->MySQL)"""

	import random
	
	dadi = random.SystemRandom()
	pausa_tra_le_query = 23 # numero di secondi tra un query e l'altra. in questo modo sono poco più di 3700 query al giorno
		
	while True:
		logit('PBL Expire: inizio')
		controllate = cancellate = 0
		db = connetto_db()
		db.execute("select CIDR from CIDR  where CATEGORY='pbl' and LASTUPDATE < (CURRENT_TIMESTAMP() - INTERVAL 2 MONTH) order by RAND()")
		elenco_cidr = db.fetchall()
		if not elenco_cidr:
			logit('PBL Expire: nessuna voce da controllare. Riprovo tra 24 ore')
			db.close()
			time.sleep(86400)
		else:
			for CIDR in elenco_cidr: # per ogni CIDR
				logit('PBL Expire: controllo '+CIDR[0])
				controllate = controllate + 1 # incremento il numero di voci controllat
				CIDR = netaddr.IPNetwork(CIDR[0])
				ip_to_test = CIDR[dadi.randint(0, CIDR.size - 1)] # estraggo un IP a caso della CIDR
				if not fucklog_utils.is_pbl(ip_to_test): # se non risulta più in PBL
					cancellate = cancellate + 1 # incremento le voci cancellate
					logit('PBL Expire: elimino '+str(CIDR)+' - controllate: '+str(controllate)+' - cancellate: '+str(cancellate))
					db.execute("delete from CIDR where CIDR=%s", (CIDR,))
					thread.start_new_thread(aggiorna_cidrarc(), (1, ))
				else:
					db.execute("update CIDR set LASTUPDATE=CURRENT_TIMESTAMP where CIDR=%s", (CIDR,))
				time.sleep(pausa_tra_le_query)

def logit(text):
	lock_output_log_file.acquire()
	now = datetime.datetime.now()
	log_file.write(now.strftime('%H:%M:%S')+" - "+text+'\n')
	log_file.flush()
	lock_output_log_file.release()

def update_stats():
	global today_ip_blocked, all_ip_blocked

	lock_stats_update.acquire()
	file_mrtg_stats.seek(0)
	file_mrtg_stats.truncate(0)
	file_mrtg_stats.write(str(all_ip_blocked)+'\n'+str(today_ip_blocked)+'\n')
	file_mrtg_stats.write(str(today_ip_blocked)+'/'+str(all_ip_blocked)+'\n')
	file_mrtg_stats.write('spam\n')
	file_mrtg_stats.flush()
	lock_stats_update.release()

def gia_in_blocco(IP):
	"""Accetto una stringa con IP/CIDR.
	Restituisco Vero se l'IP è gia' bloccato in IPTABLES (controllando Blocked->Fucklog->MySQL)."""
	
	db = connetto_db()
	db.execute('select IP from BLOCKED where IP=%s', (IP,))
	tmp = db.fetchone()
	if tmp:
		return True
	else:
		return False
	
def verifica_manuale_pbl(IP):
	"""Ricevo un IP e lo metto in coda per la verifica via WEB (PblUrk->Fucklog->MySQL)"""
	
	db = connetto_db()
	try:
		db.execute("insert into PBLURL (URL) values (%s)", (IP,))
	except:
		pass
	os.system("echo 'http://mail.gelma.net/pbl_check.php'|mail -s 'cekka "+IP+"' andrea.gelmini@gmail.com")

def blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per):
	"""Ricevo IP e numero di giorni.
	Metto in IPTables e aggiorno Blocked->Fucklog->Mysql."""
	
	global today_ip_blocked, all_ip_blocked
	db = connetto_db()
	
	fino_al_timestamp = str( datetime.datetime.now() + datetime.timedelta(days=bloccalo_per) ) # calcolo il timestamp di fine
	os.system("/sbin/iptables -A 'fucklog' -s "+indirizzo_da_bloccare+" --protocol tcp --dport 25 -j DROP")
	
	db.execute("insert into BLOCKED (IP, END) values (%s, %s)", (indirizzo_da_bloccare, fino_al_timestamp))

	today_ip_blocked += 1
	all_ip_blocked   += 1

def ip_gia_in_cidr(IP):
	"""Ricevo un IP e torno la sua eventuale classe CIDR da CidrArc->Fucklog->Mysql"""
	
	IP = netaddr.IPAddress(IP)
	db = connetto_db()
	db.execute('select CIDR from CIDRARC where IPSTART <=%s and IPEND >=%s', (int(IP), int(IP)))
	IP = db.fetchone()
	db.close()
	if IP:
		return IP[0]
	else:
		return False

def parse_log(Id):
	global db, today_ip_blocked, all_ip_blocked

	while True:
		for log_line in os.popen(grep_command):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo)
				m = regexp.match(log_line) # applico le regexp
				if m: # se combaciano
					if not gia_in_blocco(m.group(2)): # controllo che l'IP non sia gia' bloccato
						IP, DNS, FROM, TO = m.group(2), m.group(1), m.group(3), m.group(4) # estrapolo i dati
						if DNS == 'unknown': DNS = None
						CIDR_dello_IP = ip_gia_in_cidr(IP) # controllo se l'IP appartiene ad una classe nota
						if CIDR_dello_IP: # qui lavoro sulla CIDR
							if gia_in_blocco(CIDR_dello_IP): # controllo che la CIDR dell'IP non sia gia' bloccata
								continue
							else:
								indirizzo_da_bloccare = CIDR_dello_IP # ricavo il valore per iptables
								db.execute('select COUNTER from CIDR where CIDR=%s', (CIDR_dello_IP,)) # ricavo fino a quando bloccarlo
								tmp = db.fetchone()
								if tmp:
									bloccalo_per = tmp[0] + 1
								else:
									bloccalo_per = 1
								try: # aggiorno il blocco nel DB
									db.execute("update CIDR set counter=%s where CIDR=%s", (bloccalo_per, CIDR_dello_IP))
								except:
									pass								
						else: # qui lavoro sul singolo IP
							#riattiva il controllo seguente
							if fucklog_utils.is_pbl(IP): # diversamente continuo il lavoro sul singolo IP, che se fa parte di una CIDR PBL non nota, viene accodato per l'inserimento manuale
								verifica_manuale_pbl(IP)
							# ricavo per quante volte è gia' stato bloccato
							db.execute('select COUNTER from IP where IP=INET_ATON(%s)', (IP,))
							tmp = db.fetchone()
							if tmp:
								bloccalo_per = tmp[0] + 1
							else:
								bloccalo_per = 1
							# aggiorno contatore in MySQL (Ip->Fucklog->MySql)
							try:
								db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, fucklog_utils.geoip_from_ip(IP)))
							except db.IntegrityError:
								db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
							indirizzo_da_bloccare = IP
						blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per)
						TReason = 'HELO' if REASON else 'RBL'
						logit("Parse: "+indirizzo_da_bloccare+'|'+str(bloccalo_per)+'|'+str(DNS)+'|'+FROM+'|'+TO+'|'+TReason)
		update_stats()
		time.sleep(60*interval)

if __name__ == "__main__":
	# Todo list:
	# controllo per unica istanza in esecuzione

	db = connetto_db()

	# Qui ci va il resume delle regole di IPTables
	
	for flag in ['F', 'X']: # chain flush and remove
		os.system("/sbin/iptables -"+flag+" fucklog")
	os.system("/sbin/iptables -N fucklog")

	# sego tutte le voci più vecchie di ora
	# conto il numero totale di regole
	# conto le regole attivate oggi
	
	if True: # controllo il file di log
		if os.path.isfile(postfix_log_file):
			grep_command = "/bin/grep --mmap -E '(fully-qualified|blocked)' " + postfix_log_file
		else:
			logit("Errore sul log file")
			print "Problema sul file di log", postfix_log_file
			sys.exit(-1)
	
	#thread.start_new_thread(aggiorna_lasso,				(3, ))
	#thread.start_new_thread(aggiorna_uce,				(4, ))
	#thread.start_new_thread(pbl_expire,				(5, ))
	#thread.start_new_thread(aggiorna_pbl,				(6,	))
	#thread.start_new_thread(rimozione_ip_vecchi			(7, ))
	#thread.start_new_thread(parse_log,					(10, ))
	
	# altre operazioni ciclicle
	# calcolo quanto manca alla mezzanotte
	# secs_of_sleep = ((datetime.datetime.now().replace(hour=23,minute=59,second=59) - datetime.datetime.now()).seconds)+10
	# time.sleep(secs_of_sleep)
	# today_ip_blocked = 0 # azzero il contatore giornaliero
	# fucklog_utils.geoip_db = False # Barbatrucco per forzare il refresh del DB di geolocalizzazione
	
	while True:
		command = raw_input("What's up:")
		if command == "q":
			logit("Main: clean shutdown")
			sys.exit()
		if command == "s":
			logit("Stats: "+str(today_ip_blocked)+"/"+str(all_ip_blocked)+'-'+str(len(list_of_iptables_chains)))
			print "   Today IP / all IP blocked:", today_ip_blocked, "/",  all_ip_blocked,  ". Chains: ", len(list_of_iptables_chains)