<?php

####################################
# Config.php                       #
# SURFids 2.10                     #
# Changeset 002                    #
# 12-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
# Auke Folkerts                    #
####################################

#
# Called from sensor whenever a configuration changes. Updates the 
# database with the new sensor configuration. Elements included:
#
# keyname : name of  the sensor
# method : 'normal' or 'vlan'. 
# interface : string  that contains primary interface
#

####################################
# Changelog:
####################################
# 002 Added revision stuff
# 001 Initial release
####################################

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$status_offline = 0;
$status_online = 1;
$status_disabled = 3;

$allowed_get = array(
		"strip_html_escape_keyname",
		"strip_html_escape_method",
		"strip_html_escape_interface",
		"strip_html_escape_trunk",
		"int_rev",
		"strip_html_escape_interfacedev",
		"strip_html_escape_trunkdev",
		"ip_dns1",
		"ip_dns2",
		"strip_html_escape_version",
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

############
# Revision #
############
if (isset($clean['rev'])) {
	$rev = $clean['rev'];
} else {
	echo "ERRNO: 94\n";
	echo "ERROR: No revision present\n";
	$err = 1;
}

#############
# DNS 1 & 2 #
#############
if (isset($clean['dns1'])) {
	$dns1 = $clean['dns1'];
}
if (isset($clean['dns2'])) {
	$dns2 = $clean['dns2'];
}


###########
# Version #
###########

if (isset($clean['version'])) {
	$version = $clean['version'];
}

##############
# mainconf   #
##############
if (isset($clean['interface'])) {
	$mainconf = $clean['interface'];
} else {
	echo "ERRNO: 93\n";
	echo "ERROR: Details for 'interface' not present.\n";
	$err = 1;
}
if (isset($clean['interfacedev'])) {
	$mainif = $clean['interfacedev'];
} else {
	echo "ERRNO: 101\n";
	echo "ERROR: No interface device specified";
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
	
	if (isset($clean['trunkdev'])) {
		$trunk_dev = $clean['trunkdev'];
	} else {
		echo "ERRNO: 101\n";
		echo "No trunk device specified\n";
		$err = 1;
	}
}


############
# Check if sensor entry exists
#
# If no record exists for VLANid 0, add it. This is done to
# to cope with legacy systems in which vlanid 0 was not necessary.
############
/*
$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname' AND vlanid = 0";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {

    $sql_vlans = "SELECT * FROM sensors WHERE keyname = '$keyname' ORDER BY vlanid";
    $result_vlans = pg_query($pgconn, $sql_vlans);
    $numrows_vlans = pg_num_rows($result_vlans);

    if ($numrows_vlans == 0) {
      echo "ERRNO: 96\n";
      echo "ERROR: Sensor '$keyname' does not exist!\n";
      $err = 1;
    } else {
       $row = pg_fetch_assoc($result_vlans);
       # fetch row with lowest vlan id
       $r_ip = $row['remoteip'];
       $l_ip = $row['localip'];
       $org = $row['organisation'];

       $sql_insert = "INSERT INTO sensors (keyname, organisation, vlanid) VALUES ('$keyname', $org, 0)";
       echo $sql_insert;
       pg_query($pgconn, $sql_insert);
       echo "NOTE: Added vlan 0 record1\n";
    }
}
*/
# Check if sensor is offline
#$sql_active = "SELECT vlanid FROM sensors WHERE keyname = '$keyname' AND status = 1";
#$result_active = pg_query($pgconn, $sql_active);
#while ($row = pg_fetch_assoc($result_active)) {
#    $vlan = $row['vlanid'];
#    echo "ERRNO: 97\n";
#    echo "ERROR: VLAN $vlan still active!\n";
#    $err = 1;
#}

################################################################################
# Version check
################################################################################
# When the client updates its configuration, it increases a (local) counter 
# ('rev') and sends this along with the new configuration. If the server
# version is lower, the supplied config overwrites the server-stored settings. 
# If the server version is _not_ lower, this means that the serverside config 
# has been adjusted through other means (webinterface f.e.). The client is 
# notified of this, and the settings are unchanged.
################################################################################

# Fetch revision from DB
$sql_rev = "SELECT rev FROM sensor_details WHERE keyname = '$keyname'";
$result_rev = pg_query($pgconn, $sql_rev);
if (pg_num_rows($result_rev) == 0) {
    $sql_check = "SELECT id FROM sensors WHERE keyname = '$keyname'";
    $result_check = pg_query($pgconn, $sql_check);
    $num = pg_num_rows($result_check);
    if ($num == 0) {
    	echo "ERRNO: 98\n";
	    echo "ERROR: Sensor '$keyname' does not exist\n";
    	$err = 1;
    } elseif ($num > 0) {
        $sql_ins = "INSERT INTO sensor_details (keyname) VALUES ('$keyname')";
        $res = pg_query($pgconn, $sql_ins);
        $db_rev = 0;
    } else {
    	echo "ERRNO: 98\n";
	    echo "ERROR: Sensor '$keyname' does not exist\n";
    	$err = 1;
    }
} else {
    $row = pg_fetch_assoc($result_rev);
    $db_rev = $row['rev'];
}

# Compare revisions. Only continue if  the client provides a newer version
# of the configuration.
if ($db_rev >= $rev) {
	echo "ERRNO: 99\n";
	echo "ERROR: Version on server ($db_rev) more recent than own ($rev). Refusing to overwrite.\n";
	$err = 1;
}

# bail if we had errors
if ($err != 0) {
	exit;
}
logsys($f_log_info, "SAVE_CONF", "Saving sensor configuration");

################################################################################
# Update configuration to the database
################################################################################

if ($method == "normal") {
	# Store the network configuration string
    $sql = "UPDATE sensors SET status = 0, networkconfig = '$mainconf' WHERE keyname = '$keyname' AND vlanid = 0";
    $result_sql = pg_query($pgconn, $sql);

	$sql = "UPDATE sensor_details SET sensortype = 'normal', mainconf = '$mainconf', mainif = '$mainif', rev = $rev ";
    $sql .= " WHERE keyname = '$keyname'";
	$result_sql = pg_query($pgconn, $sql);

	# Disable all configured vlan sensor entries
	$sql = "UPDATE sensors SET status = 3 WHERE keyname = '$keyname' AND NOT vlanid = 0";
	$result_sql = pg_query($pgconn, $sql);
} elseif ($method = "vlan") {
	# disable all vlans
	$sql = "UPDATE sensors SET status = 3 WHERE keyname = '$keyname'";
	echo "$sql\n";
	$result_sql = pg_query($pgconn, $sql);

	# Store configuration of main interface in database.
	$sql = "UPDATE sensor_details SET sensortype = 'vlan', mainconf = '$mainconf', mainif = '$mainif', trunkif = '$trunk_dev', rev = $rev ";
    $sql .= " WHERE keyname = '$keyname'";
	echo "$sql\n";
	$result_sql = pg_query($pgconn, $sql);

	# store configuration of all vlans in database
	# $trunk consists of multiple 'vlan_configuration_entries', separated by '!'.
	$configured_vlans = split("!", $trunk);
	
	foreach ($configured_vlans as $vlan) {
		# 'vlan_configuration_entries' are a (vlan_id, vlanconf, description) 
		# tuple, separated by a comma.
		list($vlan_id, $vlanconf, $vlan_desc) = explode(",", $vlan);
		echo "vlan config: $vlan = $vlan_id, $vlanconf, $vlan_desc\n";

		$sql = "SELECT id FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlan_id'";
		echo "$sql\n";
		$sql_result = pg_query($pgconn, $sql);
		$numrows = pg_num_rows($sql_result);

		# Add row for this vlan if does not exist yet
		if ($numrows == 0) {
			$sql = "SELECT organisation FROM sensors WHERE keyname = '$keyname'";
			$sql_result = pg_query($pgconn, $sql);
			$row = pg_fetch_assoc($sql_result);
			$orgid = $row['organisation'];
			$sql_add = "INSERT INTO sensors (keyname, organisation, vlanid, tap, tapip, laststart, laststop, uptime) VALUES ('$keyname', $orgid, $vlan_id, '', '0.0.0.0', 0, 0, 0)";
			$result_add = pg_query($pgconn, $sql_add);
		}

		# Update configuration
        $sql = "UPDATE sensors SET status = 0, label = '$vlan_desc', networkconfig = '$vlanconf' WHERE keyname = '$keyname' AND vlanid = '$vlan_id'";
        $result_sql = pg_query($pgconn, $sql);
	}
}

###############################
# Continuing with main script #
###############################

$sql_sensors = "SELECT osversion, remoteip, dns1, dns2 FROM sensor_details WHERE keyname = '$keyname'";
$result_sensors = pg_query($pgconn, $sql_sensors);
if ($err == 0) {
    # Check if there is an action to be taken.
	$row = pg_fetch_assoc($result_sensors);

	echo "#######-Taken actions-#######\n";

	# If version supplied, update to the database
	if (isset($version) && $row['osversion'] != $version) {
		echo "[Database] Updated version string.\n";
		$sql_update_version = "UPDATE sensor_details SET osversion = '$version' WHERE keyname = '$keyname'";
		pg_query($pgconn, $sql_update_version);
	}
		
	# If remoteip has changed, update it to the database.
	if ($row['remoteip'] != $remoteip) {
		echo "[Database] Updated remote IP address.\n";
		$sql_update_remote = "UPDATE sensor_details SET remoteip = '$remoteip' WHERE keyname = '$keyname'";
		$result_update_remote = pg_query($pgconn, $sql_update_remote);
	}

	# If DNS has changed, update it to the database.
	if (isset($dns1) && $dns1 != $db_dns1) {
		echo "[Database] Updated Primary DNS server\n";
		$sql_update = "UPDATE sensor_details SET dns1 = '$dns1' WHERE keyname = '$keyname'";
		$result_update = pg_query($pgconn, $sql_update);
	}
	if (isset($dns2) && $dns2 != $db_dns2) {
		echo "[Database] Updated Primary DNS server\n";
		$sql_update = "UPDATE sensor_details SET dns2 = '$dns2' WHERE keyname = '$keyname'";
		$result_update = pg_query($pgconn, $sql_update);
	}
}

# Close the connection with the database.
pg_close($pgconn);
?>
