<?php

####################################
# Retrieve sensor config           #
# SURFids 2.10                     #
# Changeset 001                    #
# 12-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
# Auke Folkerts                    #
####################################

####################################
# Changelog:
# 001 Initial release
####################################

# Include configuration and connection information
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$err = 0;

# Get remoteip
$remoteip = $_SERVER['REMOTE_ADDR'];

$allowed_get = array(
		"strip_html_escape_keyname"
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

############
# Sensor type #
############
if ($err == 0) {
	$sql_sensors = "SELECT netconf, netconfdetail, iface_main, iface_trunk, dns1, dns2, rev FROM sensors WHERE keyname = '$keyname' AND vlanid = 0";
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
$iface_trunk = "\"\"";
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
	$db_rev = $sensor_status['rev'];
	$db_conf = $sensor_status['netconf'];
	$db_confdetail = $sensor_status['netconfdetail'];
	$db_dns1 = ($sensor_status['dns1']) ? $sensor_status['dns1'] : "\"\"";
	$db_dns2 = ($sensor_status['dns2']) ? $sensor_status['dns2'] : "\"\"";

	#########################################################################
	# Check whether client configuration is still up-2-date.
	#########################################################################

	#########################################################################
	# Server has newer configuration. 
	# Output in pythons' dictionary format so the client(sensor) can copy the
	# output verbatim into its config file.
	#########################################################################
#	if ($db_rev > $rev) {
		echo "sensortype = $sensor_type\n";
        echo "mainIf = $iface_main\n";
        echo "trunkIf = $iface_trunk\n";
        echo "dnstype = $config_main\n";
		echo "dns = $db_dns1, $db_dns2\n";
        echo "revision = $db_rev\n";
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
#	}

	# Sensor has newer configuration?
#	else if ($db_rev < $rev) {
#		$err = 97;
#		echo "ERRNO: $err\n";
#		echo "ERROR: Server configuration outdated. Did sensor forget to call save_config.php?\n";
#	}
#	else if ($db_rev == $rev) {
#		echo "[Database] Sensor configuraton up to date\n";
#	}
}

# Close the connection with the database.
pg_close($pgconn);
?>
