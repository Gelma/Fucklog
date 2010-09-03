#!/bin/bash

[ -e db_fucklog_MySQL_schema.sql ] && /usr/bin/mysqldump --skip-extended-insert  --add-drop-database --add-drop-table   --lock-all-tables  --quote-names -u fucklog -p fucklog > db_fucklog_MySQL_schema.sql
[ -e pbl_list.txt ] && /usr/bin/mysql -u fucklog -p -e 'select CIDR from PBL' fucklog |sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > pbl_list.txt
