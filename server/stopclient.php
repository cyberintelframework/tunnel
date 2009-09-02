<?php

####################################
# Stopclient info update           #
# SURFids 3.00                     #
# Changeset 002                    #
# 05-08-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
####################################

# Called by the stopclient script on the sensor. This script is used to exchange information from and to the sensor when the stopclient script
# on the sensor is run.

####################################
# Changelog:
# 001 Removed server variable stuff
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
    echo "ERROR: Localip not present.\n";
    $err = 1;
}

############
# Database #
############
$sql_sensors = "SELECT remoteip, localip FROM sensor_details WHERE keyname = '$keyname'";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {
    echo "ERRNO: 94\n";
    echo "ERROR: No record in the database for sensor: $keyname\n";
    $err = 1;
}

###############################
# Continuing with main script #
###############################
if ($err == 0) {
    $row = pg_fetch_assoc($result_sensors);
    $db_remoteip = $row['remoteip'];
    $db_localip = $row['localip'];

    # If remoteip has changed, update it to the database.
    if ($db_remoteip != $remoteip) {
        echo "[Database] Updated remote IP address.\n";
        $sql_update_remote = "UPDATE sensor_details SET remoteip = '$remoteip' WHERE keyname = '$keyname'";
        $result_update_remote = pg_query($pgconn, $sql_update_remote);
        if ($result_update_remote > 0) {
            logsys($f_log_debug, "STOP_CLIENT", "Remote IP changed from $db_remoteip to $remoteip");
        }
    }

    # If localip has changed, update it to the database.
    if ($db_localip != $localip) {
        echo "[Database] Updated local IP address.\n";
        $sql_update = "UPDATE sensor_details SET localip = '$localip' WHERE keyname = '$keyname'";
        $result_update = pg_query($pgconn, $sql_update);
        if ($result_update > 0) {
            logsys($f_log_debug, "STOP_CLIENT", "Local IP changed from $db_localip to $localip");
        }
    }
    logsys($f_log_info, "STOP_CLIENT", "Client shutdown notification");
}

# Close the connection with the database.
pg_close($pgconn);
?>
