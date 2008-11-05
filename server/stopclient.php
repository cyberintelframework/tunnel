<?php

####################################
# Stopclient info update           #
# SURFnet IDS 2.10.00              #
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
# 002 Extra check before query
# 001 Removed server variable stuff
####################################

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$allowed_get = array(
                "ip_localip",
                "int_vlanid",
                "strip_html_escape_keyname"
);
$check = extractvars($_GET, $allowed_get);
debug_input();

# Get remoteip and querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];
$prefix = "stopclient.php";

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
    logdb($prefix, 3, "NO_KEYNAME_GIVEN", $sensorid, $remoteip);
    $err = 1;
  }
} else {
  echo "ERRNO: 91\n";
  echo "ERROR: Keyname not valid.\n";
  $err = 1;
}

###########
# vlanid  #
###########
if (isset($clean['vlanid'])) {
  $vlanid = $clean['vlanid'];
} else {
  echo "ERRNO: 93\n";
  echo "ERROR: vlanid not present.\n";
  logdb($prefix, 3, "NO_VLANID_GIVEN", $sensorid, $remoteip);
  $err = 1;
}

# Get the sensorid for the logs
if ($err == 0) {
  $sql = "SELECT id FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result = pg_query($pgconn, $sql);
  $numrows = pg_num_rows($result);
  if ($numrows != 0) {
    $row = pg_fetch_assoc($result);
    $sensorid = $row['sensorid'];
  }
}

###########
# localip #
###########
if (isset($clean['localip'])) {
  $localip = $clean['localip'];
} else {
  echo "ERRNO: 92\n";
  echo "ERROR: Localip not present.\n";
  logdb($prefix, 3, "NO_LOCALIP_GIVEN", $sensorid, $remoteip);
  $err = 1;
}

############
# Database #
############
if ($err == 0) {
  $sql_sensors = "SELECT id, action, ssh, status, laststart, uptime, tapip, netconf, localip, remoteip ";
  $sql_sensors .= " FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  $numrows = pg_num_rows($result_sensors);
  if ($numrows == 0) {
    echo "ERRNO: 94\n";
    echo "ERROR: No record in the database for sensor: $keyname-$vlanid\n";
    logdb($prefix, 3, "NO_SENSOR_FOUND", $sensorid, $remoteip);
    $err = 1;
  }
}

###############################
# Continuing with main script #
###############################
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
  $tapip = $row['tapip'];
  $serverconf = $row['netconf'];
  if ($laststart != "") {
    $newuptime = $uptime + ($date - $laststart);
  } else {
    $newuptime = $uptime;
  }

  echo "############-SERVER-INFO-##########\n";
  echo "TIMESTAMP: $date_string\n";
  echo "ACTION: $action\n";
  echo "SSH: $ssh\n";
  echo "STATUS: $status\n";
  echo "TAPIP: $tapip\n";
  echo "SERVERCONF: $serverconf\n";
  echo "VLANID: $vlanid\n";
  echo "NEWUPTIME: $newuptime\n";
  echo "############-CLIENT-INFO-##########\n";
  echo "REMOTEIP: $remoteip\n";
  echo "KEYNAME: $keyname\n";
  echo "CLIENTCONF: $clientconf\n";

  echo "#######-Taken actions-#######\n";

  # If remoteip has changed, update it to the database.
  $old_remoteip = $row['remoteip'];
  if ($row['remoteip'] != $remoteip) {
    echo "Updated remote IP address.\n";
    $sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname' AND vlanid='$vlanid'";
    $result_update_remote = pg_query($pgconn, $sql_update_remote);
    logdb($prefix, 0, "DB_UPDATE_REMOTEIP", $sensorid, "$remoteip, $old_remoteip");
  }

  # If localip has changed, update it to the database.
  $old_localip = $row['localip'];
  if ($row['localip'] != $localip) {
    echo "Updated local IP address.\n";
    $sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname' AND vlanid='$vlanid'";
    $result_update = pg_query($pgconn, $sql_update);
    logdb($prefix, 0, "DB_UPDATE_LOCALIP", $sensorid, "$localip, $old_localip");
  }

  # Update the last start timestamp to the database.
  $sql_laststart = "UPDATE sensors SET status = 0, uptime = $newuptime, laststop = '$date' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  echo "SQLLASTSTART: $sql_laststart\n";
  $result_laststart = pg_query($pgconn, $sql_laststart);
  logdb($prefix, 0, "DB_UPDATE_STATUS", $sensorid, 0);
  logdb($prefix, 0, "DB_UPDATE_UPTIME", $sensorid, $newuptime);
  logdb($prefix, 0, "DB_UPDATE_LASTSTOP", $sensorid, $date);
}

# Close the connection with the database.
pg_close($pgconn);
?>
