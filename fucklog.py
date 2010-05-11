#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, os, re, shelve, sys, thread, time, MySQLdb

if True: # Global vars
	postfix_log_file = "/var/log/everything/current"
	mysql_host, mysql_user, mysql_passwd, mysql_db = "localhost", "fucklog", "pattinaggio", "fucklog"

	# vars
	interval = 10 # minutes
	RegExps = [] # list of regular expressions to apply
	RegExps.append(re.compile('.*RCPT from (.*)\[(.*)\]:.*blocked using.*from=<(.*)> to=<(.*)> proto')) # blacklist
	RegExps.append(re.compile('.*NOQUEUE: reject: RCPT from (.*)\[(.*)\].*Helo command rejected: need fully-qualified hostname; from=<(.*)> to=<(.*)> proto')) # broken helo
	iptables_chains = {}
	#queue for mysql
	persistentdb_queue = {}
	# Statistics
	today_ip_blocked = all_ip_blocked = 0
	# Locks
	lock_output_log_file = thread.allocate_lock()
	lock_ipdb = thread.allocate_lock()
	# Logfile
	output_log_file = '/tmp/.fucklog_log_file.txt'
	log_file = open(output_log_file,'a') # Open logfile
	# MRTG files
	file_mrtg_stats = open("/tmp/.fucklog_mrtg", 'w')

def logit(text):
	lock_output_log_file.acquire()
	now=datetime.datetime.now()
	log_file.write(now.strftime('%H:%M:%S')+" - "+text+'\n')
	log_file.flush()
	lock_output_log_file.release()

def update_stats():
	global today_ip_blocked,  all_ip_blocked

	file_mrtg_stats.seek(0)
	file_mrtg_stats.truncate(0)
	file_mrtg_stats.write(str(all_ip_blocked)+'\n'+str(today_ip_blocked)+'\n')
	file_mrtg_stats.write(str(today_ip_blocked)+'/'+str(all_ip_blocked)+'\n')
	file_mrtg_stats.write('spam\n')
	file_mrtg_stats.flush()

def rm_old_iptables_chains():
	global all_ip_blocked
	my_today = 'fucklog-'+str(datetime.date.today())
	for chain_name in iptables_chains.keys():
		if (chain_name < my_today):
			# select and delete every chain's IP
			for chain_ip in os.popen('/sbin/iptables -L '+chain_name+' -n'):
				if chain_ip[:4] == "DROP":
					ip_to_remove = chain_ip.split()[3]
					try:
						ipdb[ip_to_remove][0] = False
					except:
						logit("CleanIptables: IP "+ip_to_remove+" not present in DB")
					all_ip_blocked -= 1
			# remove the chain
			for flag in ['F',  'X']: #chain flush and remove
				os.system("/sbin/iptables -"+flag+" "+chain_name)
			del iptables_chains[chain_name]
			logit("CleanIptables: chain removed "+chain_name)
	update_stats()

def mrproper(Id):
	global today_ip_blocked
	while True:
		# we calculate the number of seconds 'ntil the 23:59:00 of today, and add something to go to tomorrow
		secs_of_sleep=((datetime.datetime.now().replace(hour=23,minute=59,second=59) - datetime.datetime.now()).seconds)+10
		logit("MrProper: sleep for "+str(secs_of_sleep)+" seconds")
		time.sleep(secs_of_sleep)
		lock_ipdb.acquire()
		logit("MrProper: acquire lock and start")
		today_ip_blocked = 0 # azzero la statistica giornaliera
		rm_old_iptables_chains()
		logit("MrProper: release lock and finish and copy")
		lock_ipdb.release()

def parse_log(Id):
	global today_ip_blocked,  all_ip_blocked

	while True:
		lock_ipdb.acquire()
		logit("Parse: begin read")
		for log_line in os.popen(grep_command):
			for REASON, regexp in enumerate(RegExps): # REASON=0 (rbl) 1 (helo)
				m = regexp.match(log_line) # match for regexp
				if m: # if it matches
					IP = m.group(2)
					try:
						cache_flag = ipdb[IP][0]
					except:
						cache_flag = False
					if cache_flag: # I check if it is already blocked
						pass
					else:
						DNS,  FROM,  TO = m.group(1),  m.group(3),  m.group(4) #Assign to more readable vars
						if DNS == 'unknown': # I check for reverse lookup
							DNS = None
						try:
							blocked_for_days = ipdb[IP][1]
						except:
							blocked_for_days = 0
						blocked_for_days += 1
						ipdb[IP] = [True,  blocked_for_days,  DNS,  FROM,  TO,  REASON]
						persistentdb_queue[IP] = [DNS,  FROM,  TO,  REASON, log_line]
						until_date = str(datetime.date.today( )+ datetime.timedelta(days=blocked_for_days)) # We block 'ntill...
						if not iptables_chains.has_key("fucklog-"+until_date): # We check if exists the iptables chains
							logit("Parse: create chain fucklog-"+until_date)
							os.system("/sbin/iptables -N 'fucklog-"+until_date+"'")
							iptables_chains["fucklog-"+until_date] = None
						os.system("/sbin/iptables -A 'fucklog-"+until_date+"' -s "+IP+" --protocol tcp --dport 25 -m time --datestop "+until_date+"T23:59:59 -j DROP")
						today_ip_blocked += 1
						all_ip_blocked += 1
						logit("Parse: block "+IP+' |'+str(blocked_for_days)+' |'+until_date+' |'+ str(DNS)+' |'+FROM+' |'+TO+' |'+str(REASON))
		lock_ipdb.release()
		update_stats()
		time.sleep(60*interval)

def persistentdb_push(Id):
	while True:
		time.sleep(3600)
		if len(persistentdb_queue) > 0:
			logit('MySQL: push start')
			try:
				pdb = MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_passwd, db=mysql_db)
				db = pdb.cursor()
			except:
				logit('MySQL: push abort')
				continue
			for IP in persistentdb_queue.keys():
				try:
					db.execute("""insert into IP (IP, DNS, FROOM, TOO, REASON, LINE) values (INET_ATON(%s), %s, %s, %s, %s, %s);""", (IP, persistentdb_queue[IP][0], persistentdb_queue[IP][1], persistentdb_queue[IP][2], persistentdb_queue[IP][3], persistentdb_queue[IP][4]))
				except db.IntegrityError:
					logit('MySQL: update IP '+IP)
					db.execute("update IP set DNS=%s, FROOM=%s, TOO=%s, REASON=%s, LINE=%s, counter=counter+1, DATE=CURRENT_TIMESTAMP where IP=INET_ATON(%s)", (persistentdb_queue[IP][0], persistentdb_queue[IP][1], persistentdb_queue[IP][2], persistentdb_queue[IP][3], persistentdb_queue[IP][4], IP))
				except:
					pass
				del persistentdb_queue[IP]
			pdb.close()
			logit('MySQL: push stop')

if __name__ == "__main__":
	logit("Main: "+5*"\n")
	try:
		file_to_read = sys.argv[1]
	except:
		file_to_read = postfix_log_file
	if os.path.isfile(file_to_read):
		grep_command = "/bin/grep --mmap -E '(fully-qualified|blocked)' " + file_to_read
	else:
		print "Invalid log file"
		sys.exit(-1)

	# second argument is DB file
	# ipdb is a dictionary. Key is IP, value is an array:
	# {'10.0.0.1': [		'0 - Cached (True/False)',
	#                       '1 - Days stopped (int)',
	#                       '2 - reverse dns (txt)',
	#                       '3 - From: (txt)',
	#                       '4 - To: (txt)',
	#                       '5 - Matched regexp (txt)']}
	ipdb = {}

	# Resume list of iptables chains
	for line in os.popen('/sbin/iptables -L -n|grep -i fucklog'):
		iptables_chains[line.split()[1]] = None
		logit("Main: resume chain "+line.split()[1])

	rm_old_iptables_chains()
	# And resume number of total IP blocked
	all_ip_blocked = 0
	for chain_name in iptables_chains:
		for total_output in os.popen('/sbin/iptables -L '+chain_name+' -n | /bin/grep DROP | /usr/bin/wc -l'):
			all_ip_blocked += int(total_output)
			# todo: update ipdb by IP to avoid double entry
	logit("Main: resume number of total IP blocked "+str(all_ip_blocked))

	thread.start_new_thread(parse_log,  (1, ))
	thread.start_new_thread(mrproper,  (1, ))
	thread.start_new_thread(persistentdb_push, (1,))

	while True:
		command = raw_input("What's up:")
		if command == "q":
			lock_ipdb.acquire()
			logit("Main: clean shutdown")
			sys.exit()
		if command == "s":
			logit("Stats: "+str(today_ip_blocked)+"/"+str(all_ip_blocked)+'-'+str(len(iptables_chains)))
			print "   Today IP blocked:", today_ip_blocked, "/",  all_ip_blocked,  ". Chains: ", len(iptables_chains)
			print "   Total known IP",  len(ipdb)