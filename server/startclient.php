<?php

####################################
# Startclient info update          #
# SURFnet IDS 2.10.00              #
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
# 002 Fixed static IP with status
# 001 Removed server variable
####################################

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$allowed_get = array(
                "ip_localip",
                "int_vlanid",
                "strip_html_escape_keyname",
		"strip_html_escape_ifmethod",
		"strip_html_escape_detail"
);
$check = extractvars($_GET, $allowed_get);
debug_input();

# Get remoteip and querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];
$prefix = "startclient.php";
$sensorid = "";

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
    logdb($prefix, 3, "NO_KEYNAME_GIVEN", $sensorid, $remoteip);
  }
} else {
  echo "ERRNO: 91\n";
  echo "ERROR: Keyname not valid.\n";
  logdb($prefix, 3, "NO_KEYNAME_GIVEN", $sensorid, $remoteip);
  $err = 1;
}

############
# vlan id  #
############
if (isset($clean['vlanid']) ) {
  $vlanid = $clean['vlanid'];
} else {
  echo "ERRNO: 95\n";
  echo "VLAN ID not set.\n";
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
# ifmethod #
############
if (isset($clean['ifmethod'])) {
  $clientconf = $clean['ifmethod'];
  $pattern = '/^(dhcp|static|vlans|vland)$/';
  if (!preg_match($pattern, $clientconf)) {
    echo "ERRNO: 93\n";
    echo "ERROR: Invalid client network config (ifmethod).\n";
    logdb($prefix, 3, "NO_NETCONF_GIVEN", $sensorid, $remoteip);
    $err = 1;
  } else {
    logdb($prefix, 0, "GET_NETCONF", $sensorid, "$remoteip, $clientconf");
  }
} else {
  echo "ERRNO: 93\n";
  echo "ERROR: Invalid client network config (ifmethod).\n";
  logdb($prefix, 3, "NO_NETCONF_GIVEN", $sensorid, $remoteip);
  $err = 1;
}

####################
# ifmethod detail  #
####################
if (isset($clean['detail'])) {
  $netconfdetail = $clean['detail'];
} else {
  echo "ERRNO: 94\n";
  echo "ERROR: Details of ifmethod not present.\n";
  if ($clientconf == "dhcp" || $clientconf == "vland") {
    logdb($prefix, 2, "NO_NCDETAIL_GIVEN", $sensorid, $remoteip);
  } else {
    logdb($prefix, 3, "NO_NCDETAIL_GIVEN", $sensorid, $remoteip);
  }
  $err = 1;
}

############
# Database #
############
if ($err == 0) {
  $sql_sensors = "SELECT id FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  $numrows = pg_num_rows($result_sensors);
  if ($numrows == 0) {
    $sql_sensors = "SELECT organisation FROM sensors WHERE keyname = '$keyname'";
    $result_sensors = pg_query($pgconn, $sql_sensors);
    $row = pg_fetch_assoc($result_sensors);
    $orgid = $row['organisation'];

    $sql_add_row = "INSERT INTO sensors (keyname, remoteip, localip, netconf, netconfdetail, organisation, vlanid) ";
    $sql_add_row .= " VALUES ('$keyname', '$remoteip', '$localip', '$clientconf', '$netconfdetail', $orgid, $vlanid)";
    $result_add_row = pg_query($pgconn, $sql_add_row);
    logdb($prefix, 0, "DB_ADD_SENSOR", $sensorid);
  }

  if ($clientconf == "vland" || $clientconf == "vlans") {
    $sql_reset = "UPDATE sensors SET remoteip = '0.0.0.0' WHERE keyname = '$keyname' AND vlanid = 0";
  } elseif ($clientconf == "dhcp" || $clientconf == "static") {
    $sql_reset = "UPDATE sensors SET remoteip = '0.0.0.0' WHERE keyname = '$keyname' AND NOT vlanid = 0";
  }
  $result_reset = pg_query($pgconn, $sql_reset);
 
  ###############################
  # Continuing with main script #
  ###############################
  $sql_sensors = "SELECT id, action, ssh, status, laststart, uptime, tapip, vlanid, netconf, netconfdetail, remoteip, localip ";
  $sql_sensors .= " FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_sensors = pg_query($pgconn, $sql_sensors);
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
  if ($tapip == "") {
    $tapip = "NULL";
  }
  $vlanid = $row['vlanid'];
  if ($vlanid == "0") {
    $vlaniddisplay = "NA";
  } else {
    $vlaniddisplay = $vlanid;
  }
  $serverconf = $row['netconf'];
  $detailconf = $row['netconfdetail'];
  
  echo "############-SERVER-INFO-##########\n";
  echo "TIMESTAMP: $date_string\n";
  echo "ACTION: $action\n";
  echo "SSH: $ssh\n";
  echo "STATUS: $status\n";
  echo "TAPIP: $tapip\n";
  echo "SERVERCONF: $serverconf\n";
  echo "DETAILCONF: $detailconf\n";
  echo "VLAN ID: $vlaniddisplay\n";
  echo "############-CLIENT-INFO-##########\n";
  echo "REMOTEIP: $remoteip\n";
  echo "KEYNAME: $keyname\n";
  echo "CLIENTCONF: $clientconf\n";

  echo "#######-Taken actions-#######\n";
  # If remoteip has changed, update it to the database.
  $old_remoteip = $row['remoteip'];
  if ($row['remoteip'] != $remoteip) {
    echo "Updated remote IP address.\n";
    $sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_update_remote = pg_query($pgconn, $sql_update_remote);
    logdb($prefix, 0, "DB_UPDATE_REMOTEIP", $sensorid, "$remoteip, $old_remoteip");
  }
  
  # If localip has changed, update it to the database.
  $old_localip = $row['localip'];
  if ($row['localip'] != $localip) {
    echo "Updated local IP address.\n";
    $sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_update = pg_query($pgconn, $sql_update);
    logdb($prefix, 0, "DB_UPDATE_LOCALIP", $sensorid, "$localip, $old_localip");
  }
  
  # Setting network config in the database
  $sql_netconf = "UPDATE sensors SET netconf = '$clientconf', netconfdetail = '$netconfdetail' WHERE keyname = '$keyname' and vlanid = '$vlanid'";
  $result_netconf = pg_query($pgconn, $sql_netconf);
  echo "Network config updated.\n";

  # Set status 
  if ($clientconf == "dhcp" | $clientconf == "vland") {
    $sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1, tapip = NULL WHERE keyname = '$keyname' and vlanid = '$vlanid'";
    $result_laststart = pg_query($pgconn, $sql_laststart);
    echo "Sensor status updated.\n";
    logdb($prefix, 0, "DB_UPDATE_STATUS", $sensorid, 1);
  } else {
    if ($tapip != "NULL") {
      $sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1 WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
      $result_laststart = pg_query($pgconn, $sql_laststart);
      echo "Sensor status updated.\n";
      logdb($prefix, 0, "DB_UPDATE_STATUS", $sensorid, 1);
    } else {
      $sql_laststart = "UPDATE sensors SET status = 0 WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
      $result_laststart = pg_query($pgconn, $sql_laststart);
      echo "Sensor status updated.\n";
      logdb($prefix, 0, "DB_UPDATE_STATUS", $sensorid, 0);
      logdb($prefix, 2, "NO_STATIC_TAPIP", $sensorid, 0);

      echo "ERRNO: 99\n";
      echo "ERROR: No static ip configuration on the server.\n";
    }
  }
  if ($vlanid == 0) {
    $sql_laststart = "UPDATE sensors SET status = 3 WHERE keyname = '$keyname' AND NOT vlanid = 0";
    $result_laststart = pg_query($pgconn, $sql_laststart);
  } else {
    $sql_laststart = "UPDATE sensors SET status = 3 WHERE keyname = '$keyname' AND vlanid = 0";
    $result_laststart = pg_query($pgconn, $sql_laststart);
  }
}

# Close the connection with the database.
pg_close($pgconn);
?>
