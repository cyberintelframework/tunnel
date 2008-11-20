<?php

####################################
# Startclient info update          #
# SURFids 2.00.03                  #
# Changeset 001                    #
# 22-05-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
####################################

# Called by the startclient script on the sensor. This script is used to exchange information from and to the sensor when the startclient script
# on the sensor is run.

####################################
# Changelog:
# 001 Removed server variable
####################################

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$allowed_get = array(
		"ip_localip",
		"strip_html_escape_keyname",
		);
$check = extractvars($_GET, $allowed_get);
debug_input();

# Get remoteip and querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];

# First check if all the variables are present.
$err = 0;

###########
# Keyname #
###########
if (isset($clean['keyname'])) {
	$keyname = $clean['keyname'];
	$pattern = '/^sensor[0-9]+$/';
	if (!preg_match($pattern, $keyname)) {
		echo "ERRNO: 91\n";
		echo "ERROR: Keyname not valid.\n";
		$err = 1;
	}
} else {
	echo "ERRNO: 91\n";
	echo "ERROR: Keyname not valid.\n";
	$err = 1;
}

###########
# localip #
###########
if (isset($clean['localip'])) {
	$localip = $clean['localip'];
} else {
	echo "ERRNO: 92\n";
	echo "ERROR: localip not present.\n";
	$err = 1;
}


###############################
# Continuing with main script #
###############################
$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname' AND vlanid = 0";
$result_sensors = pg_query($pgconn, $sql_sensors);
if ($err == 0) {
	$date = time();
	$date_string = date("d-m-Y H:i:s");
# Check if there is an action to be taken.
	$row = pg_fetch_assoc($result_sensors);
	$sensorid = $row['id'];
	$action = $row['action'];
	$ssh = $row['ssh'];
	$status = $row['status'];
	$laststart = $row['laststart'];
	$uptime = $row['uptime'];

	echo "############-SERVER-INFO-##########\n";
	echo "TIMESTAMP: $date_string\n";
	echo "ACTION: $action\n";
	echo "SSH: $ssh\n";
	echo "STATUS: $status\n";
	echo "############-CLIENT-INFO-##########\n";
	echo "REMOTEIP: $remoteip\n";
	echo "KEYNAME: $keyname\n";
	echo "#######-Taken actions-#######\n";


	# If remoteip has changed, update it to the database.
	if ($row['remoteip'] != $remoteip) {
		echo "Updated remote IP address.\n";
		$sql_update_remote = "UPDATE sensors SET remoteip = '$remoteip' WHERE keyname = '$keyname'";
		$result_update_remote = pg_query($pgconn, $sql_update_remote);
	}

	# If localip has changed, update it to the database.
	$db_localip = $row['localip'];

	if ($row['localip'] != $localip) {
		echo "Updated local IP address.\n";
		$sql_update = "UPDATE sensors SET localip = '$localip' WHERE keyname = '$keyname'" ;
		$result_update = pg_query($pgconn, $sql_update);
	}

	# set status, laststart for current sensor
	$sql_laststart = "UPDATE sensors SET laststart = $date, status = 1 WHERE keyname = '$keyname' and status = 0";
	echo ">>$sql_laststart<<";
	$result_laststart = pg_query($pgconn, $sql_laststart);
	echo "Sensor status updated.\n";
}


# Close the connection with the database.
pg_close($pgconn);
?>
