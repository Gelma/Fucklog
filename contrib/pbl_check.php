<?php

header( "Expires: Mon, 20 Dec 1998 01:00:00 GMT" );
header( "Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT" );
header( "Cache-Control: no-cache, must-revalidate" );
header( "Pragma: no-cache" );

# connessione al DB
$dbc = mysql_connect('localhost', 'fucklog', 'pattinaggio');
if (!dbc)
    die('Could not connect: ' . mysql_error());

$db = mysql_select_db('fucklog', $dbc);
if (!$db)
    die ('Can\'t use foo : ' . mysql_error());
# fine connessione

function sql($query){
	$risultato = mysql_query($query);
	if (!$risultato) {
		echo "Could not successfully run query ($sql) from DB: " . mysql_error();
		exit;
	}
	return $risultato;
}

function checkIpToNetwork($ip, $network) {
	$ipAddress = explode('/', $network);
	$networkLong = ip2long($ipAddress[0]);
	$x = ip2long($ipAddress[1]);
	$mask =  long2ip($x) == $ipAddress[1] ? $x : 0xffffffff << (32 - $ipAddress[1]);
	$ipLong = ip2long($ip);
	return ($ipLong & $mask) == ($networkLong & $mask);
}

function controlla_ricezione(){
	if ( $_POST ) {
		$IP   = trim($_POST["ip"]);
		$CIDR = trim($_POST["cidr"]);
		print '<br>';
		if (checkIpToNetwork($IP, $CIDR)){
			$IP = mysql_real_escape_string($IP);
			$CIDR = mysql_real_escape_string($CIDR);
			sql("update PBLURL set CIDR='".$CIDR."' where URL='".$IP."'");
		}else{
			print "<hr>";
			print "<p align=center> Valori non inseriti";
			print "<hr>";
			}
	}
}

function countdown(){
	$data = sql("select COUNT(*) AS tot from PBLURL where CIDR is null");
	while ($row = mysql_fetch_assoc($data)) {
		return $row['tot'];
	}
}

function mostra_box(){
	$data = sql("select URL from PBLURL where CIDR is null order by RAND() LIMIT 1");
	print '<FORM ACTION="'.$_SERVER["PHP_SELF"].'" METHOD="POST">';
	print '<table border=1 CELLPADDING="6" align=center>';
	while ($row = mysql_fetch_assoc($data)) {
		print '<tr><td align="center"><a href="http://www.spamhaus.org/query/bl?ip='.$row["URL"].'">'.$row["URL"].'</a></td></tr>';
		print '<tr><td align="center"><INPUT type="text" name="cidr" size="18">';
		print '<input type="hidden" name="ip" value="'.$row["URL"].'"></td></tr>';
		print '<tr><td align="center"><INPUT TYPE="SUBMIT" NAME="Invia" VALUE="Invia"></td></tr>';
		print '<tr><td align="center">'; echo countdown(); print '</td></tr>';
	}
	print '</FORM></table>';
}
?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	<HTML>
		<HEAD>
			<TITLE>PBL Check</TITLE>
			<META HTTP-EQUIV="Content-Type" content="text/html; charset=iso-8859-1">
			<META HTTP-EQUIV="Content-Language" CONTENT="it-IT">
		</HEAD>
		<BODY>
<?php
	controlla_ricezione();
	mostra_box();
?>

		</BODY>
	</HTML>