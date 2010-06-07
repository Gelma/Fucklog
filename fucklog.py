#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, os, re, shelve, sys, thread, time, fucklog_utils

if True: # Global vars
	postfix_log_file = "/var/log/everything/current"

	# vars
	cached_ips = {}
	interval = 10 # minutes
	RegExps = [] # list of regular expressions to apply
	RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # blacklist
	RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
	list_of_iptables_chains = {}
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

def rm_old_iptables_chains():
	global all_ip_blocked
	global cached_ips # probabilmente si puo' eliminare

	my_today = 'fucklog-'+str(datetime.date.today())
	for chain_name in list_of_iptables_chains.keys():
		if (chain_name < my_today):
			logit("Proper: parso la chain: "+chain_name)
			# select and delete every chain's IP
			for chain_ip in os.popen('/sbin/iptables -L '+chain_name+' -n'):
				if chain_ip.startswith("DROP"):
					ip_to_remove = chain_ip.split()[3]
					logit("Proper: leggo l'IP "+ip_to_remove)
					# se l'IP è presente nella cache
					if cached_ips.has_key(ip_to_remove):
						logit("Proper: l'IP è in cached_ips "+ip_to_remove)
						# elimino prima un eventuale valore (CIDR) associato
						if cached_ips[ip_to_remove]:
							logit("Parse: alla chiave IP è associato un valore "+cached_ips[ip_to_remove])
							try:
								del cached_ips[ cached_ips[ip_to_remove] ]
							except:
								logit("Parse: exception nella rimozione di "+cached_ips[ip_to_remove])
								pass
						# e in fine l'IP principale
						del cached_ips[ip_to_remove]
						all_ip_blocked -= 1
						logit("Proper: l'IP è stato rimosso "+ ip_to_remove)
			# remove the chain
			for flag in ['F', 'X']: # chain flush and remove
				os.system("/sbin/iptables -"+flag+" "+chain_name)
			del list_of_iptables_chains[chain_name]
			logit("CleanIptables: chain removed "+chain_name)
	update_stats()

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
		rm_old_iptables_chains()
		fucklog_utils.is_already_mapped('127.0.0.1',reset_cache=True) # Barbatrucco per forzare il flush della cache delle CIDR
		fucklog_utils.geoip_db = False # Barbatrucco per forzare il refresh del DB di geolocalizzazione
		# elimino tutti gli IP che non si sono ripresentati negli ultimi 6 mesi
		db = fucklog_utils.connetto_db()
		db.execute('delete from IP where DATE < (CURRENT_TIMESTAMP() - INTERVAL 6 MONTH)')
		db.close()

def parse_log(Id):
	global today_ip_blocked, all_ip_blocked

	if os.path.isfile(postfix_log_file):
		grep_command = "/bin/grep --mmap -E '(fully-qualified|blocked)' " + postfix_log_file
	else:
		logit("Errore sul log file")
		print "Problema sul file di log", postfix_log_file
		sys.exit(-1)

	db = fucklog_utils.connetto_db()
	Cidr_To_Block = None

	while True:
		logit("Parse: begin read log file")
		for log_line in os.popen(grep_command):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo)
				m = regexp.match(log_line) # match for regexp
				if m: # if it matches
					IP = m.group(2)
					if not cached_ips.has_key(IP):
						cached_ips[IP] = None
						aggiungi_log = ''
						# Estrapolo i dati
						DNS, FROM, TO = m.group(1), m.group(3), m.group(4) #Assign to more readable vars
						if DNS == 'unknown': DNS = None
						# recupero le ripetizioni e incremento
						db.execute('select COUNTER from IP where IP=INET_ATON(%s)', (IP,))
						tmp = db.fetchone()
						if tmp:
							blocked_for_days = tmp[0] + 1
						else:
							blocked_for_days = 1
						# aggiorno contatore persistente in MySQL
						try:
							db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, fucklog_utils.geoip_from_ip(IP)))
						except db.IntegrityError:
							db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
						# calcolo la data di termine, e controllo che esista la chain relativa
						until_date = str(datetime.date.today()+ datetime.timedelta(days=blocked_for_days))
						if not list_of_iptables_chains.has_key("fucklog-"+until_date):
							os.system("/sbin/iptables -N 'fucklog-"+until_date+"'")
							list_of_iptables_chains["fucklog-"+until_date] = None
						# se si tratta di un IP con CIDR nota, leggo la CIDR
						if fucklog_utils.is_already_mapped(IP):
							Cidr_To_Block = fucklog_utils.is_already_mapped(IP,torna_la_cidr=True)
							aggiungi_log  = 'CIDR'
							#	e se è un IP PBL non noto, lo metto in coda di soluzione via form web
						elif fucklog_utils.is_pbl(IP):
							db.execute("insert into PBLURL (URL) values (%s)", (IP,))
							aggiungi_log  = 'qPBL'
						# inserimento in IPTables
						if Cidr_To_Block: # se ho la CIDR
							if cached_ips.has_key(Cidr_To_Block): # controllo se sia gia' bloccata
								continue # nel qual caso mollo e passo alla riga successiva
							else: # diversamente, se non è gia' bloccata,
								address_for_iptables = Cidr_To_Block # la setto per il blocco
								cached_ips[Cidr_To_Block] = IP # metto la CIDR in cache e ci associo il singolo IP, per la rimozione in fase di cleanup
								Cidr_To_Block = None # resetto il valore per il prossimo giro
						else:
							address_for_iptables = IP # se non ho la CIDR blocco il singolo IP
						# invoco davvero il blocco con IPTables
						os.system("/sbin/iptables -A 'fucklog-"+until_date+"' -s "+address_for_iptables+" --protocol tcp --dport 25 -m time --datestop "+until_date+"T23:59:59 -j DROP")
						logit("Parse: "+address_for_iptables+'|'+str(blocked_for_days)+'|'+until_date+'|'+aggiungi_log+'|'+str(DNS)+'|'+FROM+'|'+TO+'|'+str(REASON))
						# aggiorno i totali
						today_ip_blocked += 1
						all_ip_blocked   += 1
		logit("Parse: end read")
		update_stats()
		time.sleep(60*interval)

if __name__ == "__main__":
	# Resume list of iptables chains and delete the old ones
	for line in os.popen("/sbin/iptables -L -n|grep  'Chain fucklog'"):
		chain_name = line.split()[1]
		for line in os.popen("/sbin/iptables -n -L "+chain_name):
			if line.startswith('DROP'):
				cached_ips[ line.split()[3] ] = None
				all_ip_blocked += 1
		list_of_iptables_chains[chain_name] = None
	rm_old_iptables_chains()

	thread.start_new_thread(parse_log,  (1, ))
	thread.start_new_thread(mrproper,   (1, ))

	while True:
		command = raw_input("What's up:")
		if command == "q":
			logit("Main: clean shutdown")
			sys.exit()
		if command == "s":
			logit("Stats: "+str(today_ip_blocked)+"/"+str(all_ip_blocked)+'-'+str(len(list_of_iptables_chains)))
			print "   Today IP / all IP blocked:", today_ip_blocked, "/",  all_ip_blocked,  ". Chains: ", len(list_of_iptables_chains)
			print "   cached_ips size:",len(cached_ips)