#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, os, re, shelve, sys, thread, time, fucklog_utils

if True:
	# Global vars
	cached_ips = {} # a breve dovrebbe sparire
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
	lock_stats_update = thread.allocate_lock()
	# Logfile
	output_log_file = '/tmp/.fucklog_log_file.txt'
	log_file = open(output_log_file,'a')
	# MRTG files
	file_mrtg_stats = open("/tmp/.fucklog_mrtg", 'w')

def aggiorna_lasso(Id):
	"""Prelevo la lista Lasso e aggiorno Cidr->Fucklog->Mysql"""
	
	import urllib, netaddr
	
	while True:
		time.sleep(129600) # aggiorna dopo 36 ore
		logit('Lasso: aggiornamento '+str(datetime.datetime.now()))
		try:
			lassofile = urllib.urlopen("http://www.spamhaus.org/drop/drop.lasso")
		except:
			logit("Lasso: aggiornamento fallito")
			time.sleep(3600)
			continue

		db = fucklog_utils.connetto_db()
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
			db.execute("insert into CIDR (CIDR, SIZE, NAME, CATEGORY) values (%s,%s,%s,'lasso')", (cidr, cidr.size, note.strip()))
		del lassofile

		db.close()

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

def mrproper(Id):
	global today_ip_blocked

	while True:
		# we calculate the number of seconds 'ntil the 23:59:59 of today
		secs_of_sleep = ((datetime.datetime.now().replace(hour=23,minute=59,second=59) - datetime.datetime.now()).seconds)+10
		#secs_of_sleep = 60 # temp
		logit("MrProper: sleep for "+str(secs_of_sleep)+" seconds")
		time.sleep(secs_of_sleep)
		logit("MrProper: cleanup start")
		today_ip_blocked = 0
		fucklog_utils.is_already_mapped('127.0.0.1',reset_cache=True) # Barbatrucco per forzare il flush della cache delle CIDR
		fucklog_utils.geoip_db = False # Barbatrucco per forzare il refresh del DB di geolocalizzazione
		# elimino tutti gli IP che non si sono ripresentati negli ultimi 6 mesi
		db = fucklog_utils.connetto_db()
		db.execute('delete from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 6 MONTH)')
		db.close()

def gia_bloccato(IP):
	"""Accetto una stringa con IP/CIDR.
	Restituisco Vero se l'IP è gia' bloccato in IPTABLES (controllando Blocked->Fucklog->MySQL)."""
	
	db = fucklog_utils.connetto_db()
	db.execute('select IP from BLOCKED where IP=%s', (IP,))
	tmp = db.fetchone()
	if tmp:
		return True
	else:
		return False
	
def verifica_manuale_pbl(IP):
	"""Ricevo un IP e lo metto in coda per la verifica via WEB (PblUrk->Fucklog->MySQL)"""
	
	db = fucklog_utils.connetto_db()
	try:
		db.execute("insert into PBLURL (URL) values (%s)", (IP,))
	except:
		pass
	os.system("echo 'http://mail.gelma.net/pbl_check.php'|mail -s 'cekka "+IP+"' andrea.gelmini@gmail.com")

def blocca_in_iptables(indirizzo_da_bloccare, bloccalo_per):
	"""Ricevo IP e numero di giorni.
	Metto in IPTables e aggiorno Blocked->Fucklog->Mysql."""
	
	global today_ip_blocked, all_ip_blocked
	db = fucklog_utils.connetto_db()
	
	fino_al_timestamp = str( datetime.datetime.now() + datetime.timedelta(days=bloccalo_per) ) # calcolo il timestamp di fine
	os.system("/sbin/iptables -A 'fucklog' -s "+indirizzo_da_bloccare+" --protocol tcp --dport 25 -j DROP")
	
	db.execute("insert into BLOCKED (IP, END) values (%s, %s)", (indirizzo_da_bloccare, fino_al_timestamp))

	today_ip_blocked += 1
	all_ip_blocked   += 1
	
def parse_log(Id):
	global db, today_ip_blocked, all_ip_blocked

	if os.path.isfile(postfix_log_file):
		grep_command = "/bin/grep --mmap -E '(fully-qualified|blocked)' " + postfix_log_file
	else:
		logit("Errore sul log file")
		print "Problema sul file di log", postfix_log_file
		sys.exit(-1)

	while True:
		for log_line in os.popen(grep_command):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo)
				m = regexp.match(log_line) # applico le regexp
				if m: # se combaciano
					if not gia_bloccato(m.group(2)): # controllo che l'IP non sia gia' bloccato
						IP, DNS, FROM, TO = m.group(2), m.group(1), m.group(3), m.group(4) # estrapolo i dati
						if DNS == 'unknown': DNS = None
						CIDR_dello_IP = fucklog_utils.is_already_mapped(IP) # controllo se l'IP appartiene ad una classe nota
						if CIDR_dello_IP: # qui lavoro sulla CIDR
							if gia_bloccato(CIDR_dello_IP): # controllo che la CIDR dell'IP non sia gia' bloccata
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
	# ricerca CIDR in tempo reale
	# partenza dei servizi in automatico
	# controllo per unica istanza in esecuzione

	db = fucklog_utils.connetto_db()

	# Qui ci va il resume delle regole di IPTables
	
	for flag in ['F', 'X']: # chain flush and remove
		os.system("/sbin/iptables -"+flag+" fucklog")
	os.system("/sbin/iptables -N fucklog")

	# sego tutte le voci più vecchie di ora
	# conto il numero totale di regole
	# conto le regole attivate oggi
	
	#thread.start_new_thread(parse_log,					(1, ))
	#thread.start_new_thread(mrproper,					(2, ))
	thread.start_new_thread(aggiorna_lasso,				(3, ))

	while True:
		command = raw_input("What's up:")
		if command == "q":
			logit("Main: clean shutdown")
			sys.exit()
		if command == "s":
			logit("Stats: "+str(today_ip_blocked)+"/"+str(all_ip_blocked)+'-'+str(len(list_of_iptables_chains)))
			print "   Today IP / all IP blocked:", today_ip_blocked, "/",  all_ip_blocked,  ". Chains: ", len(list_of_iptables_chains)
			print "   cached_ips size:",len(cached_ips)
		if command == "f":
			fucklog_utils.is_already_mapped('127.0.0.1',reset_cache=True)
			print "Forzata rilettura della tabella di CIDR"