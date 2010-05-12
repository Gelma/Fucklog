#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, os, re, shelve, sys, thread, time, MySQLdb, fucklog_utils

if True: # Global vars
	postfix_log_file = "/var/log/everything/current"
	mysql_host, mysql_user, mysql_passwd, mysql_db = "localhost", "fucklog", "pattinaggio", "fucklog"

	# vars
	interval = 15 # minutes
	RegExps = [] # list of regular expressions to apply
	RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # blacklist
	RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
	list_of_iptables_chains = {}
	# Statistics
	today_ip_blocked = all_ip_blocked = 0
	# Locks
	lock_output_log_file = thread.allocate_lock()
	update_stats_lock = thread.allocate_lock()
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
	global today_ip_blocked,  all_ip_blocked

	update_stats_lock.acquire()
	file_mrtg_stats.seek(0)
	file_mrtg_stats.truncate(0)
	file_mrtg_stats.write(str(all_ip_blocked)+'\n'+str(today_ip_blocked)+'\n')
	file_mrtg_stats.write(str(today_ip_blocked)+'/'+str(all_ip_blocked)+'\n')
	file_mrtg_stats.write('spam\n')
	file_mrtg_stats.flush()
	update_stats_lock.release()

def rm_old_iptables_chains():
	global all_ip_blocked

	my_today = 'fucklog-'+str(datetime.date.today())
	for chain_name in list_of_iptables_chains.keys():
		if (chain_name < my_today):
			# select and delete every chain's IP
			for chain_ip in os.popen('/sbin/iptables -L '+chain_name+' -n'):
				if chain_ip.startswith("DROP"):
					ip_to_remove = chain_ip.split()[3]
					try:
						del ipdb[ip_to_remove]
					except:
						logit("CleanIptables: IP "+ip_to_remove+" not present in DB")
					all_ip_blocked -= 1
			# remove the chain
			for flag in ['F',  'X']: #chain flush and remove
				os.system("/sbin/iptables -"+flag+" "+chain_name)
			del list_of_iptables_chains[chain_name]
			logit("CleanIptables: chain removed "+chain_name)
	update_stats()

def mrproper(Id):
	global today_ip_blocked
	while True:
		# we calculate the number of seconds 'ntil the 23:59:59 of today
		secs_of_sleep=((datetime.datetime.now().replace(hour=23,minute=59,second=59) - datetime.datetime.now()).seconds)+10
		#secs_of_sleep = 60 # temp
		logit("MrProper: sleep for "+str(secs_of_sleep)+" seconds")
		time.sleep(secs_of_sleep)
		logit("MrProper: cleanup start")
		today_ip_blocked = 0 # azzero la statistica giornaliera
		rm_old_iptables_chains()
		is_already_mapped('127.0.0.1',reset_cache=True) # Barbatrucco per forzare il flush della cache delle CIDR

def add_ip_to_eternity_block(IP):
	# ricevo un IP, e lo metto nella chain del blocco permanente di IPTables
	# trovare un modo fico per tenere traccia delle classi gia' presenti

	os.system("/sbin/iptables -A 'fucklog-eternity' -s "+IP+" --protocol tcp --dport 25 -j DROP")

def parse_log(Id):
	global today_ip_blocked, all_ip_blocked

	if os.path.isfile(postfix_log_file):
		grep_command = "/bin/grep --mmap -E '(fully-qualified|blocked)' " + postfix_log_file
	else:
		logit("Errore sul log file")
		print "Problema sul file di log", postfix_log_file
		sys.exit(-1)

	db = fucklog_utils.connetto_db()

	while True:
		logit("Parse: begin read log file")
		for log_line in os.popen(grep_command):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo)
				m = regexp.match(log_line) # match for regexp
				if m: # if it matches
					aggiungi_log = ''
					IP = m.group(2)
					if not ipdb.has_key(IP):
						ipdb[IP] = None
						# Estrapolo i dati
						DNS, FROM, TO = m.group(1), m.group(3), m.group(4) #Assign to more readable vars
						if DNS == 'unknown': DNS = None
						# recupero le ripetizioni e incremento
						db.execute('select COUNTER from IP where IP=INET_ATON(%s)', (IP,))
						tmp = db.fetchone()
						if tmp:
							blocked_for_days = tmp[0]
						else:
							blocked_for_days = 0
						blocked_for_days += 1
						# aggiorno totali
						today_ip_blocked += 1
						all_ip_blocked += 1
						# inserimento/update di MySQL
						try:
							db.execute("insert into IP (IP, DNS, FROOM, TOO, REASON, LINE, GEOIP) values (INET_ATON(%s), %s, %s, %s, %s, %s, %s)", (IP, DNS, FROM, TO, REASON, log_line, fucklog_utils.geoip_from_ip(IP)))
						except db.IntegrityError:
							db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (DNS, FROM, TO, REASON, log_line, IP))
						# inserimento in IPTables.
						#	se è un IP gia' noto nelle CIDR lo metto nel blocco permanente
						if fucklog_utils.is_already_mapped(IP):
							aggiungi_log = 'Permanente'
							add_ip_to_eternity_block( fucklog_utils.is_already_mapped(IP,torna_la_cidr=True) )
						#	se è un IP PBL non noto, lo metto in coda di soluzione via form web
						elif fucklog_utils.is_pbl(IP):
							aggiungi_log = 'PBL'
							db.execute("insert into PBLURL (URL) values (%s)", (ip,))
						#  il resto è la solita procedura di blocco
						until_date = str(datetime.date.today()+ datetime.timedelta(days=blocked_for_days))
						if not list_of_iptables_chains.has_key("fucklog-"+until_date): # We check if exists the iptables chains
							logit("Parse: create chain fucklog-"+until_date)
							os.system("/sbin/iptables -N 'fucklog-"+until_date+"'")
							list_of_iptables_chains["fucklog-"+until_date] = None
						os.system("/sbin/iptables -A 'fucklog-"+until_date+"' -s "+IP+" --protocol tcp --dport 25 -m time --datestop "+until_date+"T23:59:59 -j DROP")
						logit("Parse: "+IP+'|'+str(blocked_for_days)+'|'+until_date+'|'+aggiungi_log+'|'+str(DNS)+' |'+FROM+' |'+TO+' |'+str(REASON))

		update_stats()
		time.sleep(60*interval)

if __name__ == "__main__":

	ipdb = {}

	# Resume list of iptables chains and delete the old ones
	for line in os.popen("/sbin/iptables -L -n|grep  'Chain fucklog'"):
		chain_name = line.split()[1]
		for line in os.popen("/sbin/iptables -n -L "+chain_name):
			if line.startswith('DROP'):
				ipdb[ line.split()[3] ] = None
				all_ip_blocked += 1
		if chain_name != 'fucklog-eternity': list_of_iptables_chains[chain_name] = None
	rm_old_iptables_chains()

	# creo la Chain eterna
	os.system("/sbin/iptables -N 'fucklog-eternity'")

	thread.start_new_thread(parse_log,  (1, ))
	thread.start_new_thread(mrproper,   (1, ))

	while True:
		command = raw_input("What's up:")
		if command == "q":
			logit("Main: clean shutdown")
			sys.exit()
		if command == "s":
			logit("Stats: "+str(today_ip_blocked)+"/"+str(all_ip_blocked)+'-'+str(len(list_of_iptables_chains)))
			print "   Today IP blocked:", today_ip_blocked, "/",  all_ip_blocked,  ". Chains: ", len(list_of_iptables_chains)
			print "   IPdb size:",len(ipdb)