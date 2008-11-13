<?php

####################################
# Config.php                       #
# SURFids 2.00.03                  #
# Changeset 001                    #
# 22-05-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
####################################

# Called from sensor whenever a configuration changes. Updates the 
# database with the new sensor configuration.

####################################
# Changelog:
####################################

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$status_offline=0;
$status_online=1;
$status_disabled=3;

$allowed_get = array(
		"strip_html_escape_keyname",
		"strip_html_escape_method",
		"strip_html_escape_interface",
		"strip_html_escape_trunk",
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

##########
# method #
##########
if (isset($clean['method'])) {
	$method = $clean['method'];
	$pattern = '/^(vlan|normal)$/';
	if (!preg_match($pattern, $method)) {
		echo "ERRNO: 92\n";
		echo "ERROR: Invalid client network config (method='$method').\n";
		$err = 1;
	}
} else {
	echo "ERRNO: 92\n";
	echo "ERROR: Invalid client network config (method).\n";
	$err = 1;
}

##############
# interface  #
##############
if (isset($clean['interface'])) {
	$interface = $clean['interface'];
} else {
	echo "ERRNO: 93\n";
	echo "ERROR: Details for 'interface' not present.\n";
	$err = 1;
}

#########
# trunk #
#########
if ($method == "vlan") {
	if (isset($clean['trunk'])) {
		$trunk = $clean['trunk'];
	} else {
		echo "ERRNO: 95\n";
		echo "Trunk not set.\n";
		$err = 1;
	}
}

############
# Check if sensor entry exists
############
$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname'";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {
	echo "ERRNO: 96\n";
	echo "ERROR: Sensor '$keyname' does not exist!\n";
	$err = 1;
}

# Check if sensor is offline
while ($row = pg_fetch_assoc($result_sensors)) {
	if ($row['status'] == $status_active) {
		echo "ERRNO: 97\n";
		echo "ERROR: Sensor still active!\n";
		$err = 1;
	}
}

# bail if we had errors
if ($err != 0) {
	exit;
}

# Simple configuration. 
if ($method == "normal") {
	# Store the network configuration string
	$sql = "UPDATE sensors SET netconf = 'normal', netconfdetail = '$interface' WHERE keyname = '$keyname' AND vlanid = 0";
	$result_sql = pg_query($pgconn, $sql);

	# Disable all configured vlan sensor entries
	$sql = "UPDATE sensors SET status = 3 WHERE keyname = '$keyname' AND NOT vlanid = 0";
	$result_sql = pg_query($pgconn, $sql);

	# Enable the simple interface 
	$sql = "UPDATE sensors SET status = 0 WHERE keyname = '$keyname' AND vlanid = 0";
	$result_sql = pg_query($pgconn, $sql);
}

else if ($method = "vlan") {
	# disable all vlans
	$sql = "UPDATE sensors SET status = 3 WHERE keyname = '$keyname'";
	echo "$sql\n";
	$result_sql = pg_query($pgconn, $sql);

	# Store configuration of main interface in database.
	# we 'abuse' the netconfdetail field for vlan '0' for this, as we are certain
	# that it is not used for any of the vlans.
	$sql = "UPDATE sensors SET netconf = 'vlan', netconfdetail = '$interface' WHERE keyname = '$keyname' AND vlanid = 0";
	echo "$sql\n";
	$result_sql = pg_query($pgconn, $sql);

	# store configuration of all vlans in database
	# $trunk consists of multiple 'vlan_configuration_entries', separated by '!'.
	$configured_vlans = split("!", $trunk);
	
	foreach($configured_vlans as $vlan) {
		# 'vlan_configuration_entries' are a (vlan_id, netconfdetail, description) 
		# tuple, separated by a comma.
		list($vlan_id, $netconfdetail, $vlan_desc) = split(",", $vlan);
		echo "vlan config: $vlan = $vlan_id, $netconfdetail, $vlan_desc\n";

		$sql = "SELECT * FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlan_id'";
		echo "$sql\n";
		$sql_result = pg_query($pgconn, $sql);
		$numrows = pg_num_rows($sql_result);

		# Add row for this vlan if does not exist yet
		if ($numrows == 0) {
			$sql = "SELECT * FROM sensors WHERE keyname = '$keyname'";
			$sql_result = pg_query($pgconn, $sql);
			$row = pg_fetch_assoc($sql_result);
			$orgid = $row['organisation'];
			$sql_add = "INSERT INTO sensors (localip, remoteip, keyname, organisation, vlanid) VALUES ('0.0.0.0', '0.0.0.0', '$keyname', $orgid, $vlan_id)";
			$result_add = pg_query($pgconn, $sql_add);
		}

		# Update configuration
		$sql = "UPDATE sensors SET status = $status_offline, netconf = 'vlan', netconfdetail = '$netconfdetail' WHERE keyname = '$keyname' AND vlanid = '$vlan_id'";
		$result_sql = pg_query($pgconn, $sql);
	}
}

###############################
# Continuing with main script #
###############################

# DEBUG
exit;

$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
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
		$sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
		$result_update_remote = pg_query($pgconn, $sql_update_remote);
	}

	# If localip has changed, update it to the database.
	if ($row['localip'] != $localip) {
		echo "Updated local IP address.\n";
		$sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname'";
		$result_update = pg_query($pgconn, $sql_update);
	}



	# Setting network config in the database
	$sql_netconf = "UPDATE sensors SET netconf = '$clientconf', netconfdetail = '$netconfdetail' WHERE keyname = '$keyname' and vlanid = '$vlanid'";
	$result_netconf = pg_query($pgconn, $sql_netconf);
	echo "Network config updated.\n";

# Set status 
	# set status, laststart for current sensor
	$sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1, tapip = NULL WHERE keyname = '$keyname' and vlanid = '$vlanid'";
	$result_laststart = pg_query($pgconn, $sql_laststart);
	echo "Sensor status updated.\n";
}


# Close the connection with the database.
pg_close($pgconn);
?>
