#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import os
import random
import re
import subprocess
import sys
import thread
import time
import urllib

try:	
	import dns.resolver
	import dns.reversename
except:
	print """Manca il package dnspython (www.dnspython.org). Deb: python-dnspython"""
	sys.exit(-1)
try:
	import MySQLdb
except:
	print """Manca il package MySQLdb (mysql-python.sourceforge.net). Deb: python-mysqldb"""
	sys.exit(-1)
try:
	import netaddr
except:
	print """Manca il package netaddr (code.google.com/p/netaddr)."""
	sys.exit(-1)
try:
	import pygeoip
except:
	print """Manca il package pygeoip (code.google.com/p/python-geoip)."""
	sys.exit(-1)

# definizione variabili globali
mysql_host, mysql_user,\
mysql_passwd, mysql_db	= "localhost", "fucklog", "pattinaggio", "fucklog"
interval				= 5 # minutes
postfix_log_file 		= "/var/log/everything/current"
Debug					= False
contatore_pbl			= 0
# Locks
lock_output_log_file	= thread.allocate_lock()
lock_cidrarc			= thread.allocate_lock()
# GeoIP
geoip_db_file			= "/opt/GeoIP/GeoLiteCity.dat"
geoip_db				= False
# Logfile
output_log_file			= '/tmp/.log_file_fucklog.txt'
log_file 				= open(output_log_file, 'a')
# MRTG files
file_mrtg_stats			= open("/tmp/.fucklog_mrtg", 'w')
# RexExps
RegExps					= []
RegExpsReason			= ('rbl', 'helo', 'lost', 'many errors', 'norelay')
RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # RBL
RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
RegExps.append(re.compile('.*\[postfix/smtpd\] lost connection after .* from (.*)\[(.*)\]')) # lost connection
RegExps.append(re.compile('.*\[postfix/smtpd\] too many errors after .* from (.*)\[(.*)\]')) # too many errors
RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\].*Relay access denied.*from=<(.*)> to=<(.*)> proto')) # rely access denied

def aggiorna_cidrarc():
	"""Prendo il contenuto di Cidr->Fucklog->MySQL, riduco alle classi minime, e infilo il risultato in CidrArc->Fucklog-MySQL"""

	if lock_cidrarc.locked():
		logit('AggCidrarc: aggiornamento già in esecuzione, tralascio.')
		return

	lock_cidrarc.acquire()
	logit('AggCidrarc: inizio')
	cronometro = time.time()
	db = connetto_db()
	db.execute('(select INET_NTOA(IP) from IP) UNION (SELECT CIDR from CIDR)') # Unisco e le CIDR e i singoli IP
	lista_cidrs_nuovi = set([c[0] for c in db.fetchall()])
	logit('AggCidrarc: totale CIDR iniziali', len(lista_cidrs_nuovi))
	lista_cidrs_nuovi = set(netaddr.cidr_merge(lista_cidrs_nuovi))
	logit('AggCidrarc: totale CIDR finali', len(lista_cidrs_nuovi))
	db.execute('select CIDR from CIDRARC')
	lista_cidrs_vecchi = set([netaddr.IPNetwork(c[0]) for c in db.fetchall()])

	for cidr in lista_cidrs_nuovi: # aggiungo i nuovi
		if cidr not in lista_cidrs_vecchi:
			cidr = netaddr.IPNetwork(cidr)
			if cidr.size != 1: # non voglio le classi /32
				logit('AggCidrarc: aggiungo', cidr)
				db.execute('insert into CIDRARC (CIDR, IPSTART, IPEND, SIZE) values (%s, %s, %s, %s)', (cidr, int(cidr[0]), int(cidr[-1]), cidr.size))

	for cidr in lista_cidrs_vecchi: # cancello i vecchi
		if cidr not in lista_cidrs_nuovi:
			logit('AggCidrarc: rimuovo', cidr)
			db.execute('delete from CIDRARC where CIDR=%s', (cidr,))

	db.close()
	logit('AggCidrarc: completato in', time.time() - cronometro, 'secondi')
	lock_cidrarc.release()

def aggiorna_lasso(Id):
	"""Prelevo la lista Lasso e aggiorno Cidr->Fucklog->Mysql"""

	while True:
		dormi_fino_alle(4, 44)
		logit('Lasso: aggiornamento', datetime.datetime.now())
		try:
			lassofile = urllib.urlopen("http://www.spamhaus.org/drop/drop.lasso")
		except:
			logit("Lasso: aggiornamento fallito")
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
				logit('Lasso: errore con', cidr)
				continue
			try:
				db.execute("insert into CIDR (CIDR, SIZE, NAME, CATEGORY) values (%s,%s,%s,'lasso')", (cidr, cidr.size, note.strip()))
			except:
				logit('Lasso: errore db con', cidr)
		del lassofile

		db.close()

def aggiorna_uce(Id):
	"""Aggiorno la lista UCE2 in Cidr->Fucklog->MySQL"""

	while True:
		dormi_fino_alle(5, 55)
		logit('UCE: aggiornamento', datetime.datetime.now())

		#variante con UCE3: os.system('/usr/bin/rsync -aPz --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-3.uceprotect.net /tmp/.dnsbl-3.uceprotect.net')
		returncode = os.system('/usr/bin/rsync -aqz --no-motd --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-2.uceprotect.net /tmp/.dnsbl-2.uceprotect.net')
		if returncode != 0:
			logit('UCE: errore con rsync')
			continue

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
				logit('UCE: CIDR formalmente sbagliata', cidr)
				continue
			try:
				db.execute("insert into CIDR(CIDR, NAME, SIZE, CATEGORY) values (%s,%s,%s,'uce')", (cidr, note, cidr.size))
			except:
				pass # CIDR gia' presente nel DB

		db.close()
		aggiorna_cidrarc() # temporaneamente, faccio l'update dopo l'ultima operazione

def aggiorna_pbl(Id):
	"""Controllo le CIDR di PBL inserite via web e le attivo (PblUrl->Fucklog->MySQL)"""

	while True:
		time.sleep(3600)
		logit('WebPBL: inizio')
		db = connetto_db()
		db.execute("select URL, CIDR from PBLURL where CIDR is NOT null") # Prelevo le CIDR inserite via Web
		for row in db.fetchall():
			IP = row[0]
			CIDR = row[1]

			try: # controllo la validita' dei dati
				tmp = netaddr.IPAddress(IP)
			except:
				logit('WebPBL: IP non valido', IP)
				db.execute("delete from PBLURL where URL=%s", (IP,))
				continue
			try:
				CIDR = netaddr.IPNetwork(CIDR)
			except:
				logit("WebPBL: CIDR non valida", CIDR)
				db.execute("delete from PBLURL where URL=%s", (IP,))
				continue

			#if ip_gia_in_cidr(IP): # da riflettere: l'IP potrebbe gia' risultare in CIDR per altre classi intervenute nel frattempo
			#	logit("WebPBL: gia' mappato "+IP)
			#	db.execute("delete from PBLURL where URL=%s",(IP,))
			#	continue

			if not netaddr.ip.all_matching_cidrs(netaddr.IPAddress(IP), [netaddr.IPNetwork(CIDR), ]):
				logit("WebPBL: IP/CIDR non combaciano", IP, CIDR)
				db.execute("delete from PBLURL where URL=%s", (IP,))
				continue

			try: # tutto ok, quindi inserisco
				db.execute("insert into CIDR (CIDR, SIZE, CATEGORY) values (%s,%s,'pbl')", (CIDR, CIDR.size))
			except:
				logit("WebPBL: fallito inserimento", CIDR)
			db.execute("delete from PBLURL where URL=%s", (IP,))

		# ripeto il controllo su tutti gli IP rimasti
		db.execute("select URL from PBLURL where CIDR is null")
		for row in db.fetchall():
			IP = row[0]
			try:
				tmp = netaddr.IPAddress(IP)
			except:
				logit('WebPBL: non è un IP valido', IP)
				db.execute("delete from PBLURL where URL=%s", (IP,))
				continue
			if ip_gia_in_cidr(IP):
				logit("WebPBL: gia' mappato", IP)
				db.execute("delete from PBLURL where URL=%s", (IP,))
		db.close()

def blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per):
	"""Ricevo IP e numero di giorni. Metto in IPTables e aggiorno Blocked->Fucklog->Mysql"""
		
	fino_al_timestamp = str(datetime.datetime.now() + datetime.timedelta(hours=12 * bloccalo_per)) # calcolo il timestamp di fine
	if subprocess.call(['/sbin/iptables', '-A', 'fucklog', '-s', indirizzo_da_bloccare, '--protocol', 'tcp', '--dport', '25', '-j', 'DROP'], shell=False):
		logit('BloccaIpTables: errore IpTables', indirizzo_da_bloccare)
	else:
		db = connetto_db()
		db.execute("insert into BLOCKED (IP, END) values (%s, %s)", (indirizzo_da_bloccare, fino_al_timestamp))
		db.close()

def connetto_db():
	"""Torno una connessione al DB MySQL"""

	try:
		return MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_passwd, db=mysql_db).cursor()
	except:
		print "Fottuta la connessione al DB"
		logit('Connetto_db: errore nella connesione')
		time.sleep(5)
		sys.exit(-1)

def dormi_fino_alle(ore, minuti):
	"""Ricevo un orario nel formato h:m, e dormo fino ad allora"""

	time.sleep((datetime.datetime.now().replace(hour=ore, minute=minuti, second=0) - datetime.datetime.now()).seconds)

def gia_in_blocco(IP):
	"""Ricevo un IP/CIDR. Restituisco Vero se l'IP è gia' bloccato in IPTABLES (controllando Blocked->Fucklog->MySQL)."""

	db = connetto_db()
	db.execute('select IP from BLOCKED where IP=%s', (IP,))
	tmp = db.fetchone()
	if tmp:
		if Debug: logit('ControlloIptables:', IP, 'risulta in IpTables ', tmp[0])
		return True
	else:
		return False

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

def ip_in_pbl(IP):
	"""Accetto un IP. Torno Url/False se l'IP è in PBL"""

	global contatore_pbl

	contatore_pbl += 1
	qstr = "%s.pbl.spamhaus.org." % '.'.join(reversed(IP.split('.'))) # Giro IP: 1.2.3.4 -> 4.3.2.1
	try:
		qa = dns.resolver.query(qstr, 'TXT')
	except dns.exception.DNSException:
		return False
	for rr in qa:
		for s in rr.strings:
			return s

def lettore(Id):
	"""Leggo regolarmente il log di Postfix, e smazzo gli IP che trovo"""

	global db

	while True:
		logit('Log: nuovo giro')
		cronometro = time.time()
		for log_line in os.popen(grep_command):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo) 2 (lost connection) 3 (too many errors) 4 (relay access)
				m = regexp.match(log_line) # applico le regexp
				if m: # se combaciano
					if REASON == 0 or REASON == 1 or REASON == 4:
						IP, DNS, FROM, TO = m.group(2), m.group(1), m.group(3), m.group(4) # estrapolo i dati
					else: # se quindi REASON è 2 oppure 3
						IP, DNS, FROM, TO = m.group(2), m.group(1), None, None
						if IP == 'unknown' or DNS != 'unknown': continue
					if not gia_in_blocco(IP): # controllo che l'IP non sia gia' bloccato
						if Debug: logit('Log:', IP, 'non bloccato')
						if DNS == 'unknown': DNS = None
						CIDR_dello_IP = ip_gia_in_cidr(IP) # controllo se l'IP appartiene ad una classe nota
						if CIDR_dello_IP: # se è di classe nota
							if Debug: logit('Log:', IP, 'è di una classe nota')
							if gia_in_blocco(CIDR_dello_IP): # controllo che la CIDR dell'IP non sia gia' bloccata
								if Debug: logit('Log:', IP, 'risulta la sua CIDR già in iptables', CIDR_dello_IP)
								continue
							else: # se non è gia' bloccato
								db.execute('select COUNTER from CIDRARC where CIDR=%s', (CIDR_dello_IP,)) # ricavo fino a quando bloccarlo
								tmp = db.fetchone()
								if tmp: bloccalo_per = tmp[0] + 1
								else: bloccalo_per = 1
								try: # aggiorno il contatore nel DB
									db.execute("update CIDRARC set counter=%s where CIDR=%s", (bloccalo_per, CIDR_dello_IP))
								except:
									logit('Log: problema aggiornamento CIDR', CIDR_dello_IP)
								indirizzo_da_bloccare = CIDR_dello_IP # definisco l'IP da bloccare
								if Debug: logit('Log:', IP, 'blocco la CIDR', indirizzo_da_bloccare, 'con moltiplicatore ', bloccalo_per)
								try: # ma aggiorno anche il singolo IP nell'elenco IP, per avere chi ha innescato la CIDR
									db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, nazione_dello_ip(IP)))
								except db.IntegrityError:
									db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))								
						else: # se non ricado in nessuna classe nota, opero sulla singola voce
							if ip_in_pbl(IP): # se risulta in PBL, ma non nelle CIDR, accodo per il controllo manuale
								if Debug: logit('Log:', IP, 'risulta in PBL. Lo accodo per il web')
								verifica_manuale_pbl(IP)
							db.execute('select COUNTER from IP where IP=INET_ATON(%s)', (IP,)) # ricavo fino a quando bloccarlo
							tmp = db.fetchone()
							if tmp: bloccalo_per = tmp[0] + 1
							else: bloccalo_per = 1
							try: # aggiorno contatore in MySQL (Ip->Fucklog->MySql)
								db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, nazione_dello_ip(IP)))
							except db.IntegrityError:
								db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
							indirizzo_da_bloccare = IP
						if Debug: logit('Log:', IP, 'bloccato con moltiplicatore', bloccalo_per)
						blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per)
						logit("Log:", indirizzo_da_bloccare, '|', bloccalo_per, '|', DNS, '|', FROM, '|', TO, '|', RegExpsReason[REASON])
		logit('Log: controllato in', time.time() - cronometro, 'secondi')
		time.sleep(60 * interval)

def logit(*args):
	"""Ricevo un numero di argomenti a piacere, li salvo come unica stringa nei log"""

	linea_log = datetime.datetime.now().strftime('%H:%M:%S') + ': '

	try:
		linea_log += ' '.join(args)
	except: # desumo che siano presenti argomenti non testuali
		for item in args:
			linea_log += ' ' + str(item)

	lock_output_log_file.acquire()
	log_file.write(linea_log + '\n')
	log_file.flush()
	lock_output_log_file.release()

def nazione_dello_ip(IP):
	"""Ricevo un IP, ne torno la nazione"""

	global geoip_db

	if geoip_db is False:
		geoip_db = pygeoip.GeoIP(geoip_db_file)
	try:
		return geoip_db.country_name_by_addr(IP)
	except:
		return None

def pbl_expire(Id):
	"""Controllo tutte le CIDR PBL più vecchie di due mesi, ed eventualmente le sego (Cidr->Fucklog->MySQL)"""

	dadi = random.SystemRandom()
	pausa_tra_le_query = 23 # numero di secondi tra un query e l'altra. in questo modo sono poco più di 3700 query al giorno

	time.sleep(120) # per evitare lo storm ad ogni ripartenza

	while True:
		logit('PBL Expire: inizio')
		cidr_controllate = cidr_cancellate = 0
		db = connetto_db()
		db.execute("select CIDR from CIDR where CATEGORY='pbl' and LASTUPDATE < (CURRENT_TIMESTAMP() - INTERVAL 2 MONTH) order by RAND()")
		elenco_cidr = db.fetchall()
		if not elenco_cidr:
			logit('PBL Expire: nessuna voce da controllare. Riprovo tra 24 ore')
			db.close()
			time.sleep(86400)
		else:
			for CIDR in elenco_cidr:
				cidr_controllate += 1 # incremento il numero di voci controllate
				CIDR = netaddr.IPNetwork(CIDR[0])
				ip_to_test = CIDR[dadi.randint(0, CIDR.size - 1)] # estraggo un IP a caso della CIDR
				if not ip_gia_in_cidr(ip_to_test): # se non risulta più in PBL
					cidr_cancellate += 1 # incremento le voci cancellate
					logit('PBL Expire: elimino', CIDR, '- controllate:', cidr_controllate, '- cancellate:', cidr_cancellate)
					db.execute("delete from CIDR where CIDR=%s", (CIDR,))
				else:
					db.execute("update CIDR set LASTUPDATE=CURRENT_TIMESTAMP where CIDR=%s", (CIDR,))
				time.sleep(pausa_tra_le_query)

def rimozione_ip_vecchi(Id):
	"""Leggo Ip->Fucklog->MySQL e rimuovo gli IP che da più di 4 mesi non spammano"""

	while True:
		#time.sleep(28800) # A fine anno riabilito questo
		dormi_fino_alle(1, 11)
		logit('RimozioneIP: inizio')
		db = connetto_db()
		db.execute('select count(*) from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 4 MONTH)')
		tmp = db.fetchone()
		if tmp[0] != 0: # ho IP da eliminare
			logit('RimozioneIP: rimossi', tmp[0], 'IP')
			db.execute('delete from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 4 MONTH)')
		db.close()

def scadenza_iptables(Id):
	"""Rimuovo le regole di IpTables scadute"""

	db = connetto_db()

	while True:
		time.sleep(900) # ogni quarto d'ora
		db.execute('select IP from BLOCKED where END < CURRENT_TIMESTAMP()')
		for IP in db.fetchall():
			if subprocess.call(['/sbin/iptables', '-D', 'fucklog', '-s', IP[0], '--protocol', 'tcp', '--dport', '25', '-j', 'DROP'], shell=False):
				logit('DelIpTables: errore su rimozione', IP[0])
				continue
			else:
				db.execute('delete from BLOCKED where IP=%s', (IP[0],))
				logit('DelIpTables: segato', IP[0])

def statistiche_mrtg(Id):
	"""Aggiorno a cadenza fissa le statistiche per MRTG"""

	db = connetto_db()

	while True:
		db.execute("select count(*) from BLOCKED where CAST(BEGIN AS DATE)=CURDATE()") 
		tmp = db.fetchone()
		ip_di_oggi = str(tmp[0])

		db.execute("select count(*) from BLOCKED")
		tmp = db.fetchone()
		ip_totali = str(tmp[0])

		file_mrtg_stats.seek(0)
		file_mrtg_stats.truncate(0)
		file_mrtg_stats.write(ip_totali + '\n' + ip_di_oggi + '\n')
		file_mrtg_stats.write(ip_di_oggi + '/' + ip_totali + '\n')
		file_mrtg_stats.write('spam\n')
		file_mrtg_stats.flush()
		time.sleep(9 * 60)

def verifica_manuale_pbl(IP): 
	"""Ricevo un IP e lo metto in coda per la verifica via WEB (PblUrl->Fucklog->MySQL)"""

	db = connetto_db()
	try:
		db.execute("insert into PBLURL (URL) values (%s)", (IP,))
	except:
		pass
	os.system("echo 'http://mail.gelma.net/pbl_check.php'|mail -s 'cekka " + IP + "' andrea.gelmini@gmail.com")

if __name__ == "__main__":
	# Todo list:
	# controllo per unica istanza in esecuzione
	# rigenerazione sensata di CIDRARC (ora avviene una volta al giorno, forse varrebbe la pena individuare dei momenti opportuni)
	# autopartenza di mrtg
	# aggiornamento automatico geoip db (dovrebbe essere aggiornato una volta al mese)
	# rivedere i costrutti condizionati (eccessivo uso di continue)

	logit("Fucklog: start")
	db = connetto_db()

	if True: # ripristino delle regole di IpTables (va rivisto alla luce del jump di IpTables)
		logit('Main: ripristino IpTables')
		os.system("/sbin/iptables -D INPUT -p tcp --dport 25 -j fucklog") # elimino l'eventuale jump presente
		for flag in ['F', 'X']: os.system("/sbin/iptables -" + flag + " fucklog") # per poter eliminare la catena fucklog
		os.system("/sbin/iptables -N fucklog") # ricreo la catena
		os.system("/sbin/iptables -A INPUT -p tcp --dport 25 -j fucklog") # la punto
		db.execute('delete from BLOCKED where END < CURRENT_TIMESTAMP()') # disintegro le regole scadute nel frattempo
		db.execute('select IP from BLOCKED order by END') # e ripopolo
		for IP in db.fetchall(): os.system("/sbin/iptables -A 'fucklog' -s " + IP[0] + " --protocol tcp --dport 25 -j DROP")

	if True: # controllo validita' del file di log
		if os.path.isfile(postfix_log_file):
			grep_command = "/bin/grep -E '(fully-qualified|blocked|lost connection|too many errors|Relay access denied)' " + postfix_log_file
		else:
			logit("Main: postfix log file inutilizzabile", postfix_log_file)
			print "Problema sul file di log", postfix_log_file
			sys.exit(-1)

	if True: # esecuzione dei thread
		thread.start_new_thread(aggiorna_lasso, 		(1,))
		thread.start_new_thread(aggiorna_pbl, 			(2,))
		thread.start_new_thread(aggiorna_uce, 			(3,))
		thread.start_new_thread(pbl_expire, 			(4,))
		thread.start_new_thread(rimozione_ip_vecchi, 	(5,))
		thread.start_new_thread(statistiche_mrtg, 		(6,))
		thread.start_new_thread(scadenza_iptables, 		(7,))
		thread.start_new_thread(lettore, 				(8,))

	while True:
		command = raw_input("What's up:")
		if command == "q":
			logit("Main: clean shutdown")
			sys.exit()
		if command == "a":
			print "aggiornamento CidrArc"
			aggiorna_cidrarc()
		if command == "p":
			print contatore_pbl
		if command == "h":
			print "Help:\n\tq: quit\n\ta: Aggiorna CidrArc\n\tp: Stampa numero di richieste PBL\n"

