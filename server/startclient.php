<?php

####################################
# Startclient info update          #
# SURFids 3.00                     #
# Changeset 002                    #
# 18-07-2008                       #
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
        "strip_html_escape_keyname"
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

if ($err == 0) {
    logsys($f_log_info, "START_CLIENT", "Client startup notification");

    $sql_sensors = "SELECT remoteip, localip FROM sensor_details WHERE keyname = '$keyname'";
    $result_sensors = pg_query($pgconn, $sql_sensors);

    # Check if there is an action to be taken.
	$row = pg_fetch_assoc($result_sensors);
    $db_remoteip = $row['remoteip'];
    $db_localip = $row['localip'];

	echo "#######-Taken actions-#######\n";

	# If remoteip has changed, update it to the database.
    if ($remoteip != $db_remoteip) {
        $sql_update_remote = "UPDATE sensor_details SET remoteip = '$remoteip' WHERE keyname = '$keyname'";
        $result = pg_query($pgconn, $sql_update_remote);
        echo "[Database] Updated remote IP address!\n";
        logsys($f_log_debug, "START_CLIENT", "Remote IP changed from $db_remoteip to $remoteip");
    }

	# If localip has changed, update it to the database.
    if ($localip != $db_localip) {
        $sql_update = "UPDATE sensor_details SET localip = '$localip' WHERE keyname = '$keyname'" ;
        $result= pg_query($pgconn, $sql_update);
        echo "Updated local IP address!\n";
        logsys($f_log_debug, "START_CLIENT", "Local IP changed from $db_localip to $localip");
	}

    $sql_check = "SELECT distinct sensors.keyname FROM sensor_details, sensors ";
    $sql_check .= " WHERE sensor_details.remoteip = '$remoteip' AND NOT sensors.status = 3 AND sensors.keyname = sensor_details.keyname";
    $result = pg_query($pgconn, $sql_check);
    $numrows = pg_num_rows($result);

    if ($numrows == 1) {
      logsys($f_log_debug, "START_CLIENT", "$keyname identified and ready to start");
      echo "STATUS: OK\n";
    } else if ($numrows == 0) {
      logsys($f_log_error, "START_CLIENT", "$keyname does not have a record in database - connection refused");
      echo "STATUS: ERROR (not found)\n";
    } else {
      logsys($f_log_error, "START_CLIENT", "$keyname has multiple registered IP addresses. Most recent connection from '$remoteip'");
      echo "STATUS: ERROR (multi found)\n";
    }
}

# Close the connection with the database.
pg_close($pgconn);
?>
