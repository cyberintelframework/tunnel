<?php

####################################
# Status info                      #
# SURFids 2.10                     #
# Changeset 006                    #
# 25-08-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
####################################

####################################
# Changelog:
# 005 Changed logdb for rev change
# 004 Removed $server variable stuff
# 003 Fixed localip bug, added MAC address stuff
# 002 Added revision and version support
# 001 version 2.00
####################################

# Include configuration and connection information
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$err = 0;

# Get remoteip
$remoteip = $_SERVER['REMOTE_ADDR'];

$allowed_get = array(
		"strip_html_escape_keyname",
		"ip_localip",
		"int_rev",
);
$check = extractvars($_GET, $allowed_get);
debug_input();

###########
# Keyname #
###########
if (isset($clean['keyname'])) {
	$chkkey = $clean['keyname'];
	$pattern = '/^sensor[0-9]+$/';
	if (!preg_match($pattern, $chkkey)) {
		$err = 91;
		echo "ERRNO: $err\n";
		echo "ERROR: Invalid or missing sensor name!\n";
	} else {
		$keyname = $clean['keyname'];
	}
} else {
	$err = 91;
	echo "ERRNO: $err\n";
	echo "ERROR: Invalid or missing sensor name!\n";
}

###########
# localip #
###########
if (isset($clean['localip'])) {
	$localip = $clean['localip'];
} else {
	$err = 92;
	echo "ERRNO: $err\n";
	echo "ERROR: Invalid or missing local IP address!\n";
}

############
# revision #
############
if (isset($clean['rev'])) {
	$rev = $clean['rev'];
} else {
	$err = 93;
	echo "ERRNO: $err\n";
	echo "ERROR: Missing revision\n";
}

############
# Database #
############
if ($err == 0) {
	$sql_sensors = "SELECT action, ssh, status, laststart, uptime, tapip, netconf, netconfdetail,  tap, id, rev, localip, remoteip, sensormac, iface_main, iface_trunk, dns1, dns2";
	$sql_sensors .= " FROM sensors WHERE keyname = '$keyname' AND vlanid = 0";
	$result_sensors = pg_query($pgconn, $sql_sensors);
	$numrows = pg_num_rows($result_sensors);
	if ($numrows == 0) {
		$err = 95;
		echo "ERRNO: $err\n";
		echo "ERROR: Could not find database record!\n";
	}
	$sensor_status = pg_fetch_assoc($result_sensors);

	$sensor_type = $sensor_status['netconf']; 

}


###########################
# Fetch all sensor config #
###########################

$config_main = $sensor_status['netconfdetail'];
$iface_main = $sensor_status['iface_main'];

if ($sensor_type == "vlan") {
	$trunk_config = array();
	$iface_trunk = $sensor_status['iface_trunk'];

	$sql = "SELECT netconfdetail, vlanid, label FROM sensors WHERE keyname = '$keyname' AND NOT vlanid = 0 AND (status = 0 OR status = 1)";

	$result = pg_query($pgconn, $sql);
	if (pg_num_rows($result) == 0) {
		$err = 96;
		echo "ERRNO: $err\n";
		echo "ERROR: Could not find database record!\n";
		exit;
	}


	while ($row = pg_fetch_assoc($result)) {
		$trunk_config[] = array(
			'vlan' => $row['vlanid'],
			'netconfdetail' => $row['netconfdetail'],
			'description' => $row['label'],
		);
	}
}

###############################
# Continuing with main script #
###############################
if ($err == 0) {
	$date = time();
	$date_string = date("d-m-Y H:i:s");
# Check if there is an action to be taken.
	$sensorid = $sensor_status['id'];
	$action = $sensor_status['action'];
	$ssh = $sensor_status['ssh'];
	$status = $sensor_status['status'];
	$laststart = $sensor_status['laststart'];
	$uptime = $sensor_status['uptime'];
	$tap = $sensor_status['tap'];
	$tapip = $sensor_status['tapip'];
	$db_localip = $sensor_status['localip'];
	$db_remoteip = $sensor_status['remoteip'];
	$db_rev = $sensor_status['rev'];
	$db_conf = $sensor_status['netconf'];
	$db_confdetail = $sensor_status['netconfdetail'];
	$db_dns1 = $sensor_status['dns1'];
	$db_dns2 = $sensor_status['dns2'];
	$newuptime = $uptime + ($date - $laststart);

	if ($action == "") {
		$action = "NONE";
	}

	echo "############-SERVER-INFO-##########\n";
	echo "TIMESTAMP: $date_string\n";
	echo "ACTION: $action\n";
	echo "SERVERSSH: $ssh\n";
	echo "STATUS: $status\n";
	echo "TAPIP: $tapip\n";
	echo "LOCALIP: $db_localip\n";
	echo "REMOTEIP: $db_remoteip\n";
	echo "NEWUPTIME: $newuptime\n";
	echo "REVISION: $db_rev\n";
	echo "SENSORMAC: $db_mac\n";
	echo "############-CLIENT-INFO-##########\n";
	echo "REMOTEIP: $remoteip\n";
	echo "KEYNAME: $keyname\n";
	echo "REVISION: $rev\n";
	echo "LOCALIP: $localip\n";

	echo "#######-Action log-#######\n";

	#########################################################################
	# Update IP address if changed.
	#########################################################################
	if ($db_localip != $localip) {
		$sql_lip = "UPDATE sensors SET localip = '$localip' WHERE keyname = '$keyname'";
		$result_lip = pg_query($pgconn, $sql_lip);
		echo "[Database] Localip updated to $localip!\n";
	}
	if ($db_remoteip != $remoteip) {
		$sql_rip = "UPDATE sensors SET remoteip = '$remoteip' WHERE keyname = '$keyname'";
		$result_rip = pg_query($pgconn, $sql_rip);
		echo "[Database] Remoteip updated to $remoteip\n";
	}


	# Reset action flag
	if ($action != 'NONE') {
		$sql_action = "UPDATE sensors SET action = 'NONE' WHERE keyname = '$keyname'";
		$result_action = pg_query($pgconn, $sql_action);
		echo "[Database] Action command reset!\n";
	}

	#########################################################################
	# Check whether client configuration is still up-2-date.
	#########################################################################

	#########################################################################
	# Server has newer configuration. 
	# Output in pythons' dictionary format so the client(sensor) can copy the
	# output verbatim into its config file.
	#########################################################################
	# VERY IMPORTANT: 
	# This script may not generate more output after this, as the client 
	# will copy all output after 'BEGIN NEW CONFIG' into its configuration file.
	######################################################################## 
	if ($db_rev > $rev) {
		echo "Database contains newer configuration: rev $db_rev\n";
		echo "BEGIN NEW CONFIG\n";

		echo "sensortype = $sensor_type\n";
		echo "dns = \"$db_dns1\", \"$db_dns2\"\n";
		echo "[interfaces]\n";

		if ($config_main == "dhcp") {
			$ip="\"\""; $tapip="\"\""; $bc="\"\""; $nm="\"\""; $gw="\"\"";
			$type="dhcp";
		} else {
			list($ip,$tapip,$nm,$bc,$gw) = explode("|", $config_main);
			$type="static";
		}
		echo "[[$iface_main]]\n";
		echo "address = $ip\n";
		echo "tunnel = $tapip\n";
		echo "netmask = $nm\n";
		echo "broadcast = $bc\n";
		echo "gateway = $gw\n";
		echo "type = $type\n";

		if ($sensor_type == "vlan") {
			$ip="\"\""; $tapip="\"\""; $nm="\"\""; $bc="\"\""; $gw="\"\"";
			echo "[[$iface_trunk]]\n";
			echo "address = $ip\n";
			echo "tunnel = $tapip\n";
			echo "netmask = $nm\n";
			echo "broadcast = $bc\n";
			echo "gateway = $gw\n";
			echo "type = trunk\n";

			echo "[vlans]\n";
			foreach ( $trunk_config as $num => $config) {
				$vlan= $config['vlan'];
				$ncd= $config['netconfdetail'];
				$desc= $config['description'];
				if (!$desc) $desc = "\"\"";

				echo "[[$num]\n";
				if ($ncd == "dhcp") {
					$ip="\"\""; $tapip="\"\""; $bc="\"\""; $nm="\"\""; $gw="\"\"";
					$type="dhcp";
				} else {
					list($ip,$tapip,$nm,$bc,$gw) = split("|", $ncd);
					$type="static";
				}
				echo "description = $desc\n";
				echo "address = $ip\n";
				echo "tunnel = $tapip\n";
				echo "vlanid = $vlan\n";
				echo "netmask = $nm\n";
				echo "broadcast = $bc\n";
				echo "gateway = $gw\n";
				echo "type = $type\n";
			}
		}
	}

	# Sensor has newer configuration?
	else if ($db_rev < $rev) {
		$err = 97;
		echo "ERRNO: $err\n";
		echo "ERROR: Server configuration outdated. Did sensor forget to call save_config.php?\n";
	}
	else if ($db_rev == $rev) {
		echo "[Database] Sensor configuraton up to date\n";
	}
}

# Close the connection with the database.
pg_close($pgconn);
?>
