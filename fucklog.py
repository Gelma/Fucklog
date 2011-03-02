#!/usr/bin/env python
# -*- coding: utf-8 -*-

if True: # import dei moduli
	try: # quelli builtin
		import ConfigParser, datetime, getopt, inspect, multiprocessing, os, random, re, shlex, subprocess, sys, time, urllib
	except:
		import sys
		print "Errore nell'import dei moduli standard. Versione troppo vecchia dell'interprete?"
		sys.exit(-1)

	try: # quelli esterni
		import MySQLdb
	except:
		print """Manca il package MySQLdb (mysql-python.sourceforge.net). Debian/Ubuntu: apt-get install python-mysqldb"""
		sys.exit(-1)

	try: # quelli inclusi in Fucklog
		import netaddr          # Versione 0.7.5
		import pygeoip          # Versione 0.1.3
		import dns.resolver     # Versione 1.8.0 di DnsPython.org
		import dns.reversename  # Versione 1.8.0 di DnsPython.org
		import pblob
	except:
		print "Errore nell'import dei moduli specifici di Fucklog."
		sys.exit(-1)

def aggiorna_cidr():
	"""Prendo gli IP noti che ho, insieme a un po' di blacklist, meno le whitelist, e sbatto tutto in Cidr->Fucklog->MySQL"""

	if not lock_cidr.acquire(0):
		logit('aggiornamento già in esecuzione, tralascio.')
		return

	logit('inizio aggiornamento')
	cronometro = time.time()
	db = connetto_db()

	tmpfd=open(uce_dir+'tmp-blacklist','w') # preparo l'output delle blacklist

	if os.path.isfile(uce_dir+'tmp-blacklist'): # genero elenco dei miei IP/CIDR per blacklist
		db.execute('select INET_NTOA(IP) from IP UNION SELECT CIDR from PBL')
		for line in db.fetchall():
			tmpfd.write(line[0]+'\n')

	if os.path.isfile(uce_dir+'spamcannibal.org'):
		with open(uce_dir+'spamcannibal.org', 'r') as tmpfdinput: # esporto spamcannibal in CIDR
			for line in tmpfdinput:
				ip = line.split()[0]
				try:
					netaddr.IPGlob(ip)
				except:
					continue
				for cidr in netaddr.glob_to_cidrs(ip):
					tmpfd.write('%s\n' % cidr)

	if os.path.isfile(uce_dir+'antispam.imp.ch.txt'):
		with open(uce_dir+'antispam.imp.ch.txt', 'r') as tmpfdinput: # estraggo IP da antispam.imp.ch.txt
			for line in tmpfdinput:
				try: # provo a prendere il secondo elemento di ogni riga
					ip = line.split()[1]
				except:
					continue
				if ip == '0.0.0.0': # elimino il temibile 0.0.0.0
					continue
				try:
					netaddr.IPAddres(ip)
				except:
					continue
				tmpfd.write('%s\n' % ip)

	tmpfd.close() # chiudo tmp-blacklist

	tmpfd=open(uce_dir+'tmp-whitelist','w') # genero whitelist con classi private
	for private in ['10.0.0.0/8','127.0.0.0/8','172.16.0.0/12','192.168.0.0/16']:
		tmpfd.write(private+'\n')
	tmpfd.close()

	# raccatto le eventuali whitelist disponibili in giro
	for whitelist in [uce_dir+'ips.whitelisted.org', uce_dir+'dnswl_white_list.txt', uce_dir+'swinog-dnsrbl-whitelist', '/etc/postfix/whitelistip']:
		if os.path.isfile(whitelist):
			subprocess.call(shlex.split('/bin/cat '+whitelist), stdout=open(uce_dir+'tmp-whitelist', 'a'))

	file_rbl = '' # preparo gli argomenti per il cat successivo
	for rbl in ['tmp-blacklist ','dnsbl-1.uceprotect.net ', 'dnsbl-2.uceprotect.net ', 'cbl.abuseat.org ', 'psbl.txt ', 'unsubscore.com ']:
		file_rbl = uce_dir+rbl+file_rbl

	lista_cidrs_nuovi = set() # preparo l'elenco dei nuovi IP
	for line in os.popen('/bin/cat '+file_rbl+' | ./cidrmerge '+uce_dir+'tmp-whitelist'):
		line = line[:-1]
		if not line.endswith('/32'):
			lista_cidrs_nuovi.add(line)

	os.remove(uce_dir+'tmp-whitelist') # elimino i file temporanei
	os.remove(uce_dir+'tmp-blacklist')

	db.execute('select CIDR from CIDR') # preparo l'elenco dei vecchi IP (li prendo da CIDR->Fucklog->MySQL)
	lista_cidrs_vecchi = set([c[0] for c in db.fetchall()])

	for cidr in lista_cidrs_nuovi - lista_cidrs_vecchi: # aggiungo i nuovi
		try:
			cidr = netaddr.IPNetwork(cidr)
		except:
			logit('CIDR non valida in input',cidr)
			continue
		logit('aggiungo', cidr)
		db.execute('insert into CIDR (CIDR, IPSTART, IPEND, SIZE) values (%s, %s, %s, %s)', (cidr, int(cidr[0]), int(cidr[-1]), cidr.size))

	for cidr in lista_cidrs_vecchi - lista_cidrs_nuovi: # cancello i vecchi
		logit('rimuovo', cidr)
		db.execute('delete from CIDR where CIDR=%s', (cidr,))

	db.close()
	logit('completato in', time.time() - cronometro, 'secondi')
	lock_cidr.release()

def aggiorna_blacklist():
	"""Aggiorno le blacklist disponibili una volta al giorno"""

	while True:
		dormi_fino_alle(uce_ore, uce_minuti)
		logit('inizio aggiornamento')

		uce_rsync = shlex.split('/usr/bin/rsync -aqz --no-motd rsync-mirrors.uceprotect.net::RBLDNSD-ALL/ '+uce_dir)
		if subprocess.call(uce_rsync):
			logit('errore rsync UceProtect.net')

		uce_rsync = shlex.split('/usr/bin/rsync -aqz --no-motd psbl-mirror.surriel.com::psbl/psbl.txt '+uce_dir+'psbl.txt')
		if subprocess.call(uce_rsync):
			logit('errore rsync surriel.com')

		uce_rsync = shlex.split('/usr/bin/rsync -aqz --no-motd rsync://rsync.cbl.abuseat.org/cbl/list.txt '+uce_dir+'cbl.abuseat.org')
		if subprocess.call(uce_rsync):
			logit('errore rsync abuseat.org')

		uce_rsync = shlex.split('/usr/bin/rsync -aqz --no-motd rsync.spamcannibal.org::zonefiles/bl.spamcannibal.org.in.ip4set.rbl '+uce_dir+'spamcannibal.org')
		if subprocess.call(uce_rsync):
			logit('errore rsync spamcannibal')

		try:
			os.remove(uce_dir+'drop.lasso')
		except:
			pass
		if subprocess.call(shlex.split("/usr/bin/wget -q 'http://www.spamhaus.org/drop/drop.lasso' -O "+uce_dir+'drop.lasso')):
			logit('errore wget lasso')

		try:
			os.remove(uce_dir+'antispam.imp.ch.txt')
		except:
			pass
		if subprocess.call(shlex.split("/usr/bin/wget -q 'http://antispam.imp.ch/spamlist' -O "+uce_dir+'antispam.imp.ch.txt')):
			logit('errore wget antispam.imp.ch')

		try:
			os.remove(uce_dir+'swinog-dnsrbl-whitelist')
		except:
			pass
		if subprocess.call(shlex.split("/usr/bin/wget -q 'http://antispam.imp.ch/swinog-dnsrbl-whitelist' -O "+uce_dir+'swinog-dnsrbl-whitelist')):
			logit('errore wget swinog-dnsrbl-whitelist')

		uce_rsync = shlex.split('/usr/bin/rsync -aqz --no-motd rsync://rsync.unsubscore.com/LBBL/blacklist.txt '+uce_dir+'unsubscore.com')
		if subprocess.call(uce_rsync):
			logit('errore rsync unsubscore.com')

		aggiorna_cidr()

def blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per):
	"""Ricevo IP e numero di giorni. Metto in IPTables e aggiorno Blocked->Fucklog->Mysql"""

	fino_al_timestamp = str(datetime.datetime.now() + datetime.timedelta(hours=ore_di_blocco * bloccalo_per)) # calcolo il timestamp di fine
	if subprocess.call(['/sbin/iptables', '-A', 'fucklog', '-s', indirizzo_da_bloccare, '--protocol', 'tcp', '--dport', '25', '-j', 'DROP'], shell=False):
		logit('error adding IpTables rules for', indirizzo_da_bloccare)
	else:
		db = connetto_db()
		try:
			db.execute("insert into BLOCKED (IP, END) values (%s, %s)", (indirizzo_da_bloccare, fino_al_timestamp))
		except:
			logit('fallito inserimento', indirizzo_da_bloccare)
		db.close()

def block_all_cidr():
	"""I block all CIDR for a week"""

	logit('start')
	db = connetto_db()
	db.execute('SELECT CIDR from CIDR where CIDR not in (select IP from BLOCKED)')
	for cidr in db.fetchall():
		IP = cidr[0]
		if not gia_in_blocco(IP):
			blocca_in_iptables(IP, 7)
	logit('end')

def connetto_db():
	"""Torno una connessione al DB MySQL"""
	try:
		return MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_passwd, db=mysql_db).cursor()
	except:
		print "Fottuta la connessione al DB"
		logit("errore nella connesione")
		time.sleep(5)
		sys.exit(-1)

def dormi_fino_alle(ore, minuti):
	"""Ricevo un orario nel formato h:m, e dormo fino ad allora"""

	time.sleep((datetime.datetime.now().replace(hour=int(ore), minute=int(minuti), second=0) - datetime.datetime.now()).seconds)

def gia_in_blocco(IP):
	"""Ricevo un IP/CIDR. Restituisco Vero se l'IP è già bloccato in IPTABLES (controllando Blocked->Fucklog->MySQL)."""

	db = connetto_db()
	db.execute('select IP from BLOCKED where IP=%s', (IP,))
	if db.rowcount:
		return True
	else:
		return False

def ip_gia_in_cidr(IP):
	"""Ricevo un IP e torno la sua eventuale classe CIDR da Cidr->Fucklog->Mysql"""

	IP = netaddr.IPAddress(IP)
	db = connetto_db()
	db.execute('select CIDR from CIDR where IPSTART <=%s and IPEND >=%s', (int(IP), int(IP)))
	IP = db.fetchone()
	db.close()
	if IP:
		return IP[0]
	else:
		return False

def ip_in_pbl(IP):
	"""Accetto un IP. Torno Url/False se l'IP è in PBL"""

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

	fdlog = open(postfix_log_file, "r")
	fdlog_stat = os.stat(postfix_log_file)
	fdlog_inode, fdlog_size = fdlog_stat.st_ino, fdlog_stat.st_size

	while True:
		log_line = fdlog.readline()
		if not log_line:
			try:
				t_stat = os.stat(postfix_log_file)
				t_inode, t_size = t_stat.st_ino, t_stat.st_size
			except:
				logit("fallito stat di log. Rotazione?")
				time.sleep(intervallo)
				continue
			if ((t_inode != fdlog_inode) or (t_size < fdlog_size)):
				logit("cambiato logfile %s => o_inode: %s, o_size: %s ; n_inode: %s, n_size: %s" % (postfix_log_file, fdlog_inode, fdlog_size, t_inode, t_size))
				fdlog.close()
				fdlog = open(postfix_log_file, "r")
				fdlog_inode = t_inode
			fdlog_size = t_size
			time.sleep(intervallo)
		else: # diversamente parso quanto letto dal log
			for REASON, regexp in enumerate(RegExps):
				m = regexp.match(log_line) # I try RegExps
				if m: # if something matches
					if REASON == 0 or REASON == 1 or REASON == 4:
						IP, DNS, FROM, TO = m.group(2), m.group(1), m.group(3), m.group(4) # explode data
					else: # so reasons is one of 2, 3, 5 or 6
						IP, DNS, FROM, TO = m.group(2), m.group(1), None, None
						if IP == 'unknown' or DNS != 'unknown': continue
					if not gia_in_blocco(IP): # controllo che l'IP non sia già bloccato
						if Debug: logit(IP, 'non bloccato')
						if DNS == 'unknown': DNS = None
						CIDR_dello_IP = ip_gia_in_cidr(IP) # controllo se l'IP appartiene ad una classe nota
						if CIDR_dello_IP: # se è di classe nota
							if Debug: logit(IP, "è di una classe nota")
							if gia_in_blocco(CIDR_dello_IP): # controllo che la CIDR dell'IP non sia già bloccata
								if Debug: logit(IP, 'risulta la sua CIDR già in iptables', CIDR_dello_IP)
								continue
							else: # se non è già bloccato
								db.execute('select COUNTER from CIDR where CIDR=%s', (CIDR_dello_IP,)) # ricavo fino a quando bloccarlo
								if db.rowcount: # se è già noto
									bloccalo_per = db.fetchone()[0] + 1 # incremento
								else:
									bloccalo_per = 1 # diversamente parto da 1
								try: # aggiorno il contatore nel DB
									db.execute("update CIDR set counter=%s where CIDR=%s", (bloccalo_per, CIDR_dello_IP))
								except:
									logit('problema aggiornamento CIDR', CIDR_dello_IP)
								indirizzo_da_bloccare = CIDR_dello_IP # definisco l'IP da bloccare
								if Debug: logit(IP, 'blocco la CIDR', indirizzo_da_bloccare, 'con moltiplicatore ', bloccalo_per)
								try: # ma aggiorno anche il singolo IP nell'elenco IP, per avere chi ha innescato la CIDR
									db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, nazione_dello_ip(IP)))
								except db.IntegrityError:
									db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
						else: # se non ricado in nessuna classe nota, opero sulla singola voce
							if ip_in_pbl(IP): # se risulta in PBL, ma non nelle CIDR, interrogo spamhaus
								if Debug: logit(IP, 'in PBL. Looking for complete CIDR.')
								get_pbl_from_spamhaus(IP)
							db.execute('select COUNTER from IP where IP=INET_ATON(%s)', (IP,)) # ricavo fino a quando bloccarlo
							if db.rowcount:
								bloccalo_per = db.fetchone()[0] + 1
							else:
								bloccalo_per = 1
							try: # aggiorno contatore in MySQL (Ip->Fucklog->MySql)
								db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, nazione_dello_ip(IP))) # With IPv6 enabled it can crash...
							except db.IntegrityError:
								db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
							indirizzo_da_bloccare = IP
						if Debug: logit(IP, 'bloccato con moltiplicatore', bloccalo_per)
						blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per)
						logit(indirizzo_da_bloccare, '|', bloccalo_per, '|', DNS, '|', FROM, '|', TO, '|', RegExpsReason[REASON])

def logit(*args):
	"""I receive strings/iterable objects, convert them to text and put in logfile."""

	try:
		caller = inspect.stack()[1][3]
	except:
		caller = ''

	linea_log = datetime.datetime.now().strftime('%H:%M:%S') + ' (' + caller + '): '

	try:
		linea_log += ' '.join(args)
	except: # desumo che siano presenti argomenti non testuali
		for item in args:
			linea_log += ' %s' % item

	with lock_output_log_file:
		log_file.write(linea_log + '\n')
		log_file.flush()

def nazione_dello_ip(IP):
	"""Ricevo un IP, ne torno la nazione"""
	try:
		return geoip_db.country_name_by_addr(IP)
	except:
		return None

def pbl_latest_check():
	"""Everyday I re-check latest 15 days PBL entries"""

	time.sleep(180)
	while True:
		time.sleep(31536000)
		# Select PBL < 15 day update
		# Is it still blocked:
		#	do nothing
		# else:
		#	remove
		# Uhm... in this way it would double check entries updated by pbl_expire...
		# Why do this?
		# Think about this:
		# a) Spamhaus insert a CIDR in PBL
		# b) CIDR owner reclaim/fix/contact spamhaus
		# c) Spamhaus remove CIDR from PBL
		# d) We are not updated 'till next month (or check)

def pbl_expire():
	"""I check all the PBL entries older than 2 months."""

	dadi = random.SystemRandom()
	query_interval = 24 # Sleeping time between queries. So we can check 3600 CIDR/day

	time.sleep(120) # I wait to start on boot

	while True:
		cidr_checked = cidr_deleted = 0
		db = connetto_db()
		db.execute("select CIDR from PBL where LASTUPDATE < (CURRENT_TIMESTAMP() - INTERVAL 2 MONTH) order by RAND()")
		if not db.rowcount:
			logit('not enough older entry to check. I will retry in a day')
			db.close()
			time.sleep(86400)
		else:
			for CIDR in db.fetchall():
				cidr_checked += 1
				CIDR = netaddr.IPNetwork(CIDR[0])
				ip_to_test = CIDR[dadi.randint(0, CIDR.size - 1)] # I pick a random address of the CIDR pool
				# Todo: we should check more IP of same range (PBL CIDR can be smaller, or removed, but with the checked IP spamming).
				# Todo: maybe we should be check via pblob, but Spamhaus is sensitive about HTTP requests
				if not ip_in_pbl(ip_to_test):
					cidr_deleted += 1
					logit('removed', CIDR, '- checked:', cidr_checked, '- deleted:', cidr_deleted)
					db.execute("delete from PBL where CIDR=%s", (CIDR,))
				else:
					db.execute("update PBL set LASTUPDATE=CURRENT_TIMESTAMP where CIDR=%s", (CIDR,))
				time.sleep(query_interval)

def rimozione_ip_vecchi():
	"""Leggo Ip->Fucklog->MySQL e rimuovo gli IP che da più di 4 mesi non spammano"""
	# select count(*) as conta,cast(DATE as date) as quando from IP group by quando order by quando;

	while True:
		time.sleep(14400)
		db = connetto_db()
		db.execute('delete from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 4 MONTH)')
		if db.rowcount != 0:
			logit('rimossi', db.rowcount, 'IP')
		db.close()

def scadenza_iptables():
	"""Rimuovo le regole di IpTables scadute"""

	db = connetto_db()

	while True:
		time.sleep(1800) # ogni mezz'ora
		db.execute('select IP from BLOCKED where END < CURRENT_TIMESTAMP()')
		for IP in db.fetchall():
			if subprocess.call(['/sbin/iptables', '-D', 'fucklog', '-s', IP[0], '--protocol', 'tcp', '--dport', '25', '-j', 'DROP'], shell=False):
				logit('errore su rimozione', IP[0])
				continue
			else:
				db.execute('delete from BLOCKED where IP=%s', (IP[0],))
				if Debug: logit('segato', IP[0])

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
		time.sleep(5 * 60)

def get_pbl_from_spamhaus(IP):
	"""Give me an IP, I'll give you back its complete Spamhaus PBL cidr"""

	time.sleep(random.randint(1, 15)) # We delay request to avoid Spamhaus' wrath
	spob = pblob.sphPBL(IP)
	if (spob.cidr):
		db = connetto_db()
		try:
			db.execute("insert into PBL(CIDR,NAME) values (%s,%s)", (spob.cidr,spob.pbl_num))
		except:
			pass
		body = 'IP: %s - CIDR: %s - PBL: %s' % (IP, spob.cidr, spob.pbl_num) # Text for log and email
		if os.path.exists('/usr/bin/mail'):
			echo_command = shlex.split("echo '"+body+"'")
			mail_command = shlex.split("mail -s 'Fucklog: %s PBL' %s" % (spob.cidr, pbl_email))
			subprocess.Popen(mail_command, stdin=subprocess.Popen(echo_command, stdout=subprocess.PIPE).stdout, stdout=subprocess.PIPE).wait()
		logit(body)
		blocca_in_iptables(spob.cidr, 1)
	else:
		logit('(maybe) error with IP',IP,': check if they hate me')

if __name__ == "__main__":
	if True: # da fare
		# autopartenza di mrtg
		# aggiornamento automatico geoip db (dovrebbe essere aggiornato una volta al mese)
		#    primo del mese:
		#    http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
		#    utilizzare una versione di geoip db locale?
		# abbandonare MySQL in favore di sqlite?
		# aprire i file di log/mrtg solo in lettura/scrittura per root
		# inserire possibilità whitelist/blacklist personalizzate
		# now we can also have PBL complete name. Maybe it's time to re-think validation process?
		pass

	if True: # lettura della configurazione e definizione delle variabili globali
		configurazione = ConfigParser.ConfigParser()
		confp = configurazione.read(['/etc/fucklog.conf', os.path.join(os.environ["HOME"], '.fucklog.conf'), 'fucklog.conf'])
		if confp: # Non posso utilizzare logit, mi mancano troppe informazioni
			print "Main: file di configurazione letti: ",' - '.join(confp)
			del confp
		else:
			print "Main: nessun file di configurazione valido"
			sys.exit(-1)
		# Locks
		lock_output_log_file = multiprocessing.Lock()
		lock_cidr            = multiprocessing.Lock()
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
		try:
			log_file		 = open(output_log_file, 'a')
		except:
			print "Main: non posso creare il file di log: ",log_file
			sys.exit(-1)
		uce_ore, \
		uce_minuti       = configurazione.get('Generali', 'aggiorna_uce').split(":")
		uce_dir          = configurazione.get('Generali', 'uce_dir')
		if not uce_dir.startswith('/'):
			print "Main: il percordo di uce_dir",uce_dir,"deve essere assoluto"
			sys.exit(-1)
		if not uce_dir.endswith('/'):
			uce_dir = uce_dir + '/'
		if not os.path.exists(uce_dir): # se non esiste la directory per rbl
			os.mkdir(uce_dir)
			print "Main: è stata creata la directory", uce_dir
			logit("è stata creata la directory", uce_dir)
		else:
			if not os.path.isdir(uce_dir): # se non si tratta di una directory
				print "Main: ",uce_dir," non è una directory. Non posso utilizzarla."
				sys.exit(-1)
		ore_di_blocco    = configurazione.getint('Generali', 'ore_di_blocco')
		#   GeoIP
		geoip_db_file	 = configurazione.get('Generali', 'geoip_db_file')
		try:
			geoip_db     = pygeoip.GeoIP(geoip_db_file)
		except:
			geoip_db     = False
		#   MRTG
		file_mrtg		 = configurazione.get('Generali', 'mrtg_file')
		try:
			file_mrtg_stats	 = open(file_mrtg, 'w')
		except:
			print "Main: impossibile creare il file per MRTG:",file_mrtg_stats
			sys.exit(-1)
		#   PBL
		pbl_email        = configurazione.get('Generali', 'pbl_email')
		pbl_url          = configurazione.get('Generali', 'pbl_url')
		#   PIDfile
		pidfile          = '/var/run/fucklog.pid'
		# RexExps
		RegExps 	= []
		RegExpsReason	= ('rbl', 'helo', 'lost', 'many errors', 'norelay', 'timeout', '5.1.1')
		RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # RBL
		RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
		RegExps.append(re.compile('.*\[postfix/smtpd\] lost connection after .* from (.*)\[(.*)\]')) # lost connection
		RegExps.append(re.compile('.*\[postfix/smtpd\] too many errors after .* from (.*)\[(.*)\]')) # too many errors
		RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\].*Relay access denied.*from=<(.*)> to=<(.*)> proto')) # rely access denied
		RegExps.append(re.compile('.*\[postfix/smtpd\] timeout after .* from (.*)\[(.*)\]')) # timeout
		RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\]: 550 5.1.1 .* Recipient address rejected: User unknown in virtual alias table; from=<(.*)> to=<(.*)> proto')) # '5.1.1'

		NULL = open("/dev/null", "w")

	if True: # controllo degli eseguibili necessari
		for cmd in ['/usr/bin/rsync','/usr/bin/wget','./cidrmerge']:
			if not os.path.isfile(cmd):
				print "Main: necessito di",cmd
				sys.exit(-1)

	if True: # controllo istanze attive
		if os.path.isfile(pidfile): # controllo istanze attive
			if os.path.isdir('/proc/' + str(file(pidfile,'r').read())):
				print "Main: probabile ci sia un'altra istanza già in esecuzione di Fucklog. Se così non fosse, elimina",pidfile
				sys.exit(-1)
			else:
				print "Main: stale pidfile rimosso."
		file(pidfile,'w').write(str(os.getpid()))	# controllare se resta il fd aperto

	if True: # avvio e ripristino delle regole di IpTables
		try:
			opts, args = getopt.getopt(sys.argv[1:], "e", ["evita-ripristino-iptables"])
		except getopt.GetoptError:
			print "Main: opzioni non valide:",sys.argv[1:]
			sys.exit(-1)
		evita_ripristino_iptables = False
		db = connetto_db()
		for opt, a in opts:
			if opt in ('-e', '--evita-ripristino-iptables'):
				evita_ripristino_iptables = True
			logit("avvio")
		if evita_ripristino_iptables is False:
			logit('ripristino IpTables')
			if not subprocess.call(shlex.split("/sbin/iptables -L fucklog -n"), stdout=NULL): # se esiste la catena fucklog
				subprocess.call(shlex.split("/sbin/iptables -F fucklog")) # la svuoto
			else:
				subprocess.call(shlex.split("/sbin/iptables -N fucklog")) # diversamente la creo
			if (subprocess.Popen(shlex.split("/sbin/iptables -L INPUT -n"), stdout=subprocess.PIPE).stdout.read().find("fucklog") == -1): # se non esiste il jump
				subprocess.call(shlex.split("/sbin/iptables -A INPUT -p tcp --dport 25 -j fucklog")) # lo creo
			db.execute('delete from BLOCKED where END < CURRENT_TIMESTAMP()') # disintegro le regole scadute nel frattempo
			db.execute('select IP from BLOCKED order by END') # e ripopolo
			for IP in db.fetchall(): subprocess.call(shlex.split("/sbin/iptables -A 'fucklog' -s "+IP[0]+" --protocol tcp --dport 25 -j DROP"))

	if True: # controllo validità del file di log
		if not os.path.isfile(postfix_log_file):
			logit("log file inutilizzabile:", postfix_log_file," - Inesistente? Non è un file?")
			print "File di log inutilizzabile. Controllare", postfix_log_file
			sys.exit(-1)

	if True: # partenza dei thread
		elenco_thread = []
		threads = [
			aggiorna_blacklist,
			pbl_expire,
			pbl_latest_check,
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
			logit("clean shutdown")
			for thread in elenco_thread:
				thread.terminate()
			file_mrtg_stats.close()
			log_file.close()
			os.remove(pidfile)
			print "Eventualmente ricordati svuotare le regole di IpTables."
			sys.exit()
		if command == "a":
			print "aggiornamento Cidr"
			aggiorna_cidr()
		if command == 'e':
			print 'I block all Cidr for a week'
			aggiorna_cidr()
			block_all_cidr()
		if command == "h":
			print "Help:\n\tq: quit\n\ta: Aggiorna Cidr\n\te: block all CIDRs for a week\n"
