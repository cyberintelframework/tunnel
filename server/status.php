<?php

####################################
# Status info                      #
# SURFids 2.10                     #
# Changeset 006                    #
# 16-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
# Auke Folkerts                    #
####################################

####################################
# Changelog:
# 006 Changed a bit of logic
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
        "int_ssh",
        "mac_mac"
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
# SSH      #
############
if (isset($clean['ssh'])) {
	$ssh = $clean['ssh'];
} else {
	$err = 93;
	echo "ERRNO: $err\n";
	echo "ERROR: Missing SSH status\n";
}

##############
# Sensor MAC #
##############
if (isset($clean['mac'])) {
    $mac = $clean['mac'];
} else {
    $err = 94;
    echo "ERRNO: $err";
    echo "ERROR: Missing sensor MAC address\n";
}

############
# Database #
############
if ($err == 0) {
	$sql_sensors = "SELECT action, localip, remoteip, ssh, sensormac, sensortype, mainconf FROM sensor_details ";
    $sql_sensors .= " WHERE keyname = '$keyname'";
	$result_sensors = pg_query($pgconn, $sql_sensors);
	$numrows = pg_num_rows($result_sensors);
	if ($numrows == 0) {
        $sql = "SELECT id FROM sensors WHERE keyname = '$keyname'";
        $result = pg_query($pgconn, $sql);
        $numrows = pg_num_rows($result);
        if ($numrows > 0) {
            $sql_sensors = "INSERT INTO sensor_details (keyname) VALUES ('$keyname')";
            $result_sensors = pg_query($pgconn, $sql_sensors);

        	$sql_sensors = "SELECT action, localip, remoteip, ssh, sensormac FROM sensor_details ";
            $sql_sensors .= " WHERE keyname = '$keyname'";
        	$result_sensors = pg_query($pgconn, $sql_sensors);
        } else {
    		$err = 95;
	    	echo "ERRNO: $err\n";
		    echo "ERROR: Could not find database record!\n";
        }
    }
    if ($err == 0) {
    	$sensor = pg_fetch_assoc($result_sensors);
    	$action = $sensor['action'];
        $db_localip = $sensor['localip'];
        $db_remoteip = $sensor['remoteip'];
        $db_ssh = $sensor['ssh'];
        $db_mac = $sensor['sensormac'];
        $sensortype = $sensor['sensortype'];
        $mainconf = $sensor['mainconf'];
        if ($sensortype == "" || $mainconf == "") {
            echo "[Action] Request save config\n";
            echo "ACTION: SAVECONF\n";
        } elseif ($action != "" && $action != "NONE") {
            echo "ACTION: $action\n";
        }

        echo "#######-Action log-#######\n";

    	if ($db_localip != $localip) {
	    	$sql_lip = "UPDATE sensor_details SET localip = '$localip' WHERE keyname = '$keyname'";
    		$result_lip = pg_query($pgconn, $sql_lip);
		    echo "[Database] Localip updated to $localip!\n";
	    }
    	if ($db_remoteip != $remoteip) {
	    	$sql_rip = "UPDATE sensor_details SET remoteip = '$remoteip' WHERE keyname = '$keyname'";
    		$result_rip = pg_query($pgconn, $sql_rip);
		    echo "[Database] Remoteip updated to $remoteip\n";
	    }
    	if ($db_ssh != $ssh) {
	    	$sql_ssh = "UPDATE sensor_details SET ssh = '$ssh' WHERE keyname = '$keyname'";
    		$result_ssh = pg_query($pgconn, $sql_ssh);
		    echo "[Database] SSH status updated to $ssh\n";
	    }
    	if ($db_mac != $mac) {
	    	$sql_mac = "UPDATE sensor_details SET sensormac = '$mac' WHERE keyname = '$keyname'";
    		$result_mac = pg_query($pgconn, $sql_mac);
		    echo "[Database] MAC address updated to $mac\n";
	    }
    	# Reset action flag
	    if ($action != 'NONE') {
    		$sql_action = "UPDATE sensor_details SET action = 'NONE' WHERE keyname = '$keyname'";
		    $result_action = pg_query($pgconn, $sql_action);
	    	echo "[Database] Action command reset!\n";
    	}

        $tstamp = time();
        $sql_up = "UPDATE sensor_details SET lastupdate = $tstamp WHERE keyname = '$keyname'";
        $result_up = pg_query($pgconn, $sql_up);
        echo "[Database] Last update timestamp changed\n";
    }
}

# Close the connection with the database.
pg_close($pgconn);
?>
