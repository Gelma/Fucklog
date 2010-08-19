#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	import ConfigParser
	import datetime
	import multiprocessing
	import os
	import random
	import re
	import shlex
	import subprocess
	import sys
	import time
	import urllib
except:
	import sys
	print "Errore nell'import dei moduli standard. Versione troppo vecchia dell'interprete?"
	sys.exit(-1)

try:
	import netaddr          # Versione 0.7.4
	import pygeoip          # Versione 0.1.3
	import dns.resolver     # Versione 1.8.0 di DnsPython.org
	import dns.reversename  # Versione 1.8.0 di DnsPython.org
except:
	print "Errore nell'import dei moduli specifici di Fucklog."
	sys.exit(-1)

try:
	import MySQLdb
except:
	print """Manca il package MySQLdb (mysql-python.sourceforge.net). Deb: python-mysqldb"""
	sys.exit(-1)


def aggiorna_cidrarc():
	"""Prendo il contenuto di Cidr->Fucklog->MySQL, riduco alle classi minime, e infilo il risultato in CidrArc->Fucklog-MySQL"""

	if os.path.isfile('./cidrmerge'): # se ho disponibile l'eseguibile cidrmerge
		nuovo_aggiorna_cidrarc() # eseguo la nuova funzione
		return
	
	if(lock_cidrarc.acquire(0) == False):
		logit('AggCidrarc: aggiornamento già in esecuzione, tralascio.')
		return

	logit('AggCidrarc: inizio')
	cronometro = time.time()
	db = connetto_db()
	db.execute('select INET_NTOA(IP) from IP UNION SELECT CIDR from CIDR') # Unisco e le CIDR e i singoli IP
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

def aggiorna_lasso():
	"""Prelevo la lista Lasso e aggiorno Cidr->Fucklog->Mysql"""

	while True:
		dormi_fino_alle(lasso_ore, lasso_minuti)
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

def aggiorna_uce():
	"""Aggiorno la lista UCE2 in Cidr->Fucklog->MySQL"""

	# Per i limiti giornalieri, e per l'utilizzo futuro, conviene scaricare tutto l'archivio
	uce_rsync = shlex.split('/usr/bin/rsync -aqz --no-motd --compress-level=9 rsync-mirrors.uceprotect.net::RBLDNSD-ALL/ /tmp/.fucklog/uce/')

	while True:
		dormi_fino_alle(uce_ore, uce_minuti)
		logit('UCE: aggiornamento', datetime.datetime.now())
	
		if subprocess.call(uce_rsync) != 0:
			logit('UCE: errore con rsync')
			continue

		db = connetto_db()
		db.execute("delete from CIDR where CATEGORY='uce'")

		with open('/tmp/.fucklog/uce/dnsbl-2.uceprotect.net', 'r') as ucefile:
			for line in ucefile:
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
		aggiorna_cidrarc() # temporaneamente, faccio l'update dopo l'ultima operazione in senso temporale

def aggiorna_pbl():
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
		
	fino_al_timestamp = str(datetime.datetime.now() + datetime.timedelta(hours=ore_di_blocco * bloccalo_per)) # calcolo il timestamp di fine
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

	time.sleep((datetime.datetime.now().replace(hour=int(ore), minute=int(minuti), second=0) - datetime.datetime.now()).seconds)

def gia_in_blocco(IP):
	"""Ricevo un IP/CIDR. Restituisco Vero se l'IP è gia' bloccato in IPTABLES (controllando Blocked->Fucklog->MySQL)."""

	db = connetto_db()
	db.execute('select IP from BLOCKED where IP=%s', (IP,))
	if db.rowcount:
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

def lettore():
	"""Leggo regolarmente il log di Postfix, e smazzo gli IP che trovo"""

	global db

	while True:
		logit('Log: nuovo giro')
		cronometro = time.time()
		for log_line in subprocess.Popen(grep_command, shell=False, stdout=subprocess.PIPE).communicate()[0].split('\n'):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo) 2 (lost connection) 3 (too many errors) 4 (relay access) 5 (timeout)
				m = regexp.match(log_line) # applico le regexp
				if m: # se combaciano
					if REASON == 0 or REASON == 1 or REASON == 4:
						IP, DNS, FROM, TO = m.group(2), m.group(1), m.group(3), m.group(4) # estrapolo i dati
					else: # se quindi REASON è 2 oppure 3 oppure 5
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
								if db.rowcount: # se è gia' noto
									bloccalo_per = db.fetchone()[0] + 1 # incremento
								else:
									bloccalo_per = 1 # diversamente parto da 1
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
							if db.rowcount:
								bloccalo_per = db.fetchone()[0] + 1
							else:
								bloccalo_per = 1
							try: # aggiorno contatore in MySQL (Ip->Fucklog->MySql)
								db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, nazione_dello_ip(IP)))
							except db.IntegrityError:
								db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
							indirizzo_da_bloccare = IP
						if Debug: logit('Log:', IP, 'bloccato con moltiplicatore', bloccalo_per)
						blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per)
						logit("Log:", indirizzo_da_bloccare, '|', bloccalo_per, '|', DNS, '|', FROM, '|', TO, '|', RegExpsReason[REASON])
		logit('Log: controllato in', time.time() - cronometro, 'secondi')
		time.sleep(60 * intervallo)

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
	try:
		return geoip_db.country_name_by_addr(IP)
	except:
		return None

def pbl_expire():
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

def rimozione_ip_vecchi():
	"""Leggo Ip->Fucklog->MySQL e rimuovo gli IP che da più di 4 mesi non spammano"""

	while True:
		#time.sleep(28800) # A fine anno riabilito questo
		dormi_fino_alle(1, 11)
		logit('RimozioneIP: inizio')
		db = connetto_db()
		db.execute('delete from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 4 MONTH)')
		logit('RimozioneIP: rimossi', db.rowcount, 'IP')
		db.close()

def scadenza_iptables():
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

def statistiche_mrtg():
	"""Aggiorno a cadenza fissa le statistiche per MRTG"""

	db = connetto_db()

	while True:
		db.execute("select count(*) from BLOCKED where CAST(BEGIN AS DATE)=CURDATE()") 
		ip_di_oggi = str(db.fetchone()[0])

		db.execute("select count(*) from BLOCKED")
		ip_totali = str(db.fetchone()[0])

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
	if os.path.exists('/usr/bin/mail'):
		echo_command = shlex.split("echo '"+pbl_url+"'")
		mail_command = shlex.split("mail -s 'cekka %s' %s" % (IP, pbl_email))
		subprocess.Popen(mail_command, stdin=subprocess.Popen(echo_command, stdout=subprocess.PIPE).stdout, stdout=subprocess.PIPE).wait()
	else:
		logit('PBL: mancanza comando "mail"')

if __name__ == "__main__":
	# Todo list:
	# tailf
	# rigenerazione sensata di CIDRARC (renderla più frequenta una volta resa sufficientemente veloce)
	# passaggio di CIDRARC a merge esterno .c
	# autopartenza di mrtg
	# aggiornamento automatico geoip db (dovrebbe essere aggiornato una volta al mese)
	#    primo del mese:
	#    http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	#    utilizzare una versione di geoip db locale?
	# rivedere i costrutti condizionati (eccessivo uso di continue)
	# abbandonare MySQL in favore di sqlite?

	if True: # lettura della configurazione e definizione delle variabili globali
		configurazione = ConfigParser.ConfigParser()
		confp = configurazione.read(['/etc/fucklog.conf', os.path.join(os.environ["HOME"], '.fucklog.conf'), 'fucklog.conf'])
		if confp: # Non posso utilizzare logit, mi mancano troppe informazioni
			print "Main: file di configurazione letti: ",' - '.join(confp)
			del confp
		else:
			print "Main: nessun file di configurazione valido"
			sys.exit(-1)
		# MySQL
		mysql_host       = configurazione.get('MySQL', 'host', 1)
		mysql_user       = configurazione.get('MySQL', 'user', 1)
		mysql_passwd     = configurazione.get('MySQL', 'password', 1)
		mysql_db         = configurazione.get('MySQL', 'database', 1)
		# Postfix
		intervallo       = configurazione.getint('Postfix', 'intervallo')
		postfix_log_file = configurazione.get('Postfix', 'mail_log')
		# Generali
		Debug			 = configurazione.getint('Generali', 'debug')
		output_log_file	 = configurazione.get('Generali', 'log_file')
		log_file		 = open(output_log_file, 'a')
		lasso_ore, \
		lasso_minuti     = configurazione.get('Generali', 'aggiorna_lasso').split(":")
		uce_ore, \
		uce_minuti       = configurazione.get('Generali', 'aggiorna_uce').split(":")
		uce_dir          = configurazione.get('Generali', 'uce_dir')
		ore_di_blocco    = configurazione.getint('Generali', 'ore_di_blocco')
		#   GeoIP
		geoip_db_file	 = configurazione.get('Generali', 'geoip_db_file')
		try:
			geoip_db     = pygeoip.GeoIP(geoip_db_file)
		except:
			geoip_db     = False
		#   MRTG
		file_mrtg		 = configurazione.get('Generali', 'mrtg_file')
		file_mrtg_stats	 = open(file_mrtg, 'w')
		# PBL
		contatore_pbl    = 0
		pbl_email        = configurazione.get('Generali', 'pbl_email')
		pbl_url          = configurazione.get('Generali', 'pbl_url')
		# Locks
		lock_output_log_file = multiprocessing.Lock()
		lock_cidrarc         = multiprocessing.Lock()
		# PIDfile
		pidfile          = '/var/run/fucklog.pid'
		# RexExps
		RegExps					= []
		RegExpsReason			= ('rbl', 'helo', 'lost', 'many errors', 'norelay', 'timeout')
		RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # RBL
		RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
		RegExps.append(re.compile('.*\[postfix/smtpd\] lost connection after .* from (.*)\[(.*)\]')) # lost connection
		RegExps.append(re.compile('.*\[postfix/smtpd\] too many errors after .* from (.*)\[(.*)\]')) # too many errors
		RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\].*Relay access denied.*from=<(.*)> to=<(.*)> proto')) # rely access denied
		RegExps.append(re.compile('.*\[postfix/smtpd\] timeout after .* from (.*)\[(.*)\]')) # timeout

	if True: # controllo directory temporanee
		if not os.path.isdir('/tmp/.fucklog'):
			os.system('/bin/rm -fr /tmp/.fucklog')
		if not os.path.isdir('/tmp/.fucklog/uce'):
			os.system('/bin/mkdir -p /tmp/.fucklog/uce')

	if True: # controllo istanze attive
		if os.path.isfile(pidfile): # controllo istanze attive
			if os.path.isdir( '/proc/' + str( file(pidfile,'r').read() )):
				print "Main: probabile ci sia un'altra istanza gia' in esecuzione di Fucklog. Se così non fosse, elimina "+pidfile
				sys.exit(-1)
			else:
				print "Mail: stale pidfile rimosso."
		file(pidfile,'w').write(str(os.getpid()))	# controllare se resta il fd aperto

	logit("Main: partenza di Fucklog")	
	db = connetto_db()

	if True: # ripristino delle regole di IpTables
		logit('Main: ripristino IpTables')
		if not os.system("/sbin/iptables -L fucklog -n"): # se esiste la catena fucklog
			subprocess.call(shlex.split("/sbin/iptables -F fucklog")) # la svuoto
		else:
			subprocess.call(shlex.split("/sbin/iptables -N fucklog")) # diversamente la creo
		if os.system("/sbin/iptables -L INPUT -n|/bin/grep fucklog"): # se non esiste il jump presente
			subprocess.call(shlex.split("/sbin/iptables -A INPUT -p tcp --dport 25 -j fucklog")) # lo creo
		db.execute('delete from BLOCKED where END < CURRENT_TIMESTAMP()') # disintegro le regole scadute nel frattempo
		db.execute('select IP from BLOCKED order by END') # e ripopolo
		for IP in db.fetchall(): subprocess.call(shlex.split("/sbin/iptables -A 'fucklog' -s "+IP[0]+" --protocol tcp --dport 25 -j DROP"))

	if True: # controllo validita' del file di log
		if os.path.isfile(postfix_log_file):
			grep_command = "/bin/grep -E '(fully-qualified|blocked|lost connection|too many errors|Relay access denied|timeout after)' " + postfix_log_file
			grep_command = tuple(shlex.split(grep_command))
		else:
			logit("Main: postfix log file inutilizzabile", postfix_log_file)
			print "Problema sul file di log", postfix_log_file
			sys.exit(-1)

	if True: # partenza dei thread
		elenco_thread = []
		threads = [
			aggiorna_lasso,
			aggiorna_pbl,
			aggiorna_uce,
			pbl_expire,
			rimozione_ip_vecchi,
			statistiche_mrtg,
			scadenza_iptables,
			lettore
		]
		
		for thread in threads:
			tmp = multiprocessing.Process(target=thread)
			elenco_thread.append(tmp)
			tmp.start()
		del tmp

	while True:
		command = raw_input("What's up:")
		if command == "q":
			logit("Main: clean shutdown")
			for thread in elenco_thread:
				thread.terminate()
			file_mrtg_stats.close()
			log_file.close()
			os.remove(pidfile)
			print "Eventualmente ricordati svuotare le regole di IpTables."
			sys.exit()
		if command == "a":
			print "aggiornamento CidrArc"
			aggiorna_cidrarc()
		if command == "p":
			print contatore_pbl
		if command == "h":
			print "Help:\n\tq: quit\n\ta: Aggiorna CidrArc\n\tp: Stampa numero di richieste PBL\n"
