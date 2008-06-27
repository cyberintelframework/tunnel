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
                "int_vlanid",
                "strip_html_escape_keyname",
		"strip_html_escape_ifmethod",
		"strip_html_escape_detail"
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
# ifmethod #
############
if (isset($clean['ifmethod'])) {
  $clientconf = $clean['ifmethod'];
  $pattern = '/^(dhcp|static|vlans|vland)$/';
  if (!preg_match($pattern, $clientconf)) {
    echo "ERRNO: 93\n";
    echo "ERROR: Invalid client network config (ifmethod).\n";
    $err = 1;
  }
} else {
  echo "ERRNO: 93\n";
  echo "ERROR: Invalid client network config (ifmethod).\n";
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
  $err = 1;
}

############
# Database #
############
$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {
  if ($clientconf == "vland" || $clientconf == "vlans") {
    $sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname'";
    $result_sensors = pg_query($pgconn, $sql_sensors);
    $row = pg_fetch_assoc($result_sensors);
    $orgid = $row['organisation'];
    $sql_add_row = "INSERT INTO sensors (keyname, remoteip, localip, netconf, netconfdetail, organisation, vlanid) VALUES ('$keyname', '$remoteip', '$localip', '$clientconf', '$netconfdetail', $orgid, $vlanid)";
    echo "SQLADD: $sql_add_row\n";
    $result_add_row = pg_query($pgconn, $sql_add_row);
  } elseif ($clientconf == "dhcp" || $clientconf == "static") {
    $sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname'";
    $result_sensors = pg_query($pgconn, $sql_sensors);
    $row = pg_fetch_assoc($result_sensors);
    $orgid = $row['organisation'];
    $sql_add_row = "INSERT INTO sensors (keyname, remoteip, localip, netconf, netconfdetail, organisation, vlanid) VALUES ('$keyname', '$remoteip', '$localip', '$clientconf', '$netconfdetail', $orgid, $vlanid)";
    echo "SQLADD: $sql_add_row\n";
    $result_add_row = pg_query($pgconn, $sql_add_row);
  }
}

if ($clientconf == "vland" || $clientconf == "vlans") {
  $sql_reset = "UPDATE sensors SET remoteip = '0.0.0.0' WHERE keyname = '$keyname' AND vlanid = 0";
  $result_reset = pg_query($pgconn, $sql_reset);
} elseif ($clientconf == "dhcp" || $clientconf == "static") {
  $sql_reset = "UPDATE sensors SET remoteip = '0.0.0.0' WHERE keyname = '$keyname' AND NOT vlanid = 0";
  $result_reset = pg_query($pgconn, $sql_reset);
}
 
###############################
# Continuing with main script #
###############################
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
  if ($row['remoteip'] != $remoteip) {
    echo "Updated remote IP address.\n";
    $sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_update_remote = pg_query($pgconn, $sql_update_remote);
    logdb($sensorid, 14);
  }
  
  # If localip has changed, update it to the database.
  if ($row['localip'] != $localip) {
    echo "Updated local IP address.\n";
    $sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_update = pg_query($pgconn, $sql_update);
    logdb($sensorid, 13);
  }
  
  # Setting network config in the database
  $sql_netconf = "UPDATE sensors SET netconf = '$clientconf', netconfdetail = '$netconfdetail' WHERE keyname = '$keyname' and vlanid = '$vlanid'";
  $result_netconf = pg_query($pgconn, $sql_netconf);
  echo "Network config updated.\n";
  if ($clientconf != $serverconf) {
    logdb($sensorid, 12);
  }

  # Set status 
  if ($clientconf == "dhcp" | $clientconf == "vland") {
    $sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1, tapip = NULL WHERE keyname = '$keyname' and vlanid = '$vlanid'";
    $result_laststart = pg_query($pgconn, $sql_laststart);
    echo "Sensor status updated.\n";

    logdb($sensorid, 1);
  } else {
    if ($tapip != "NULL") {
      $sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1 WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
      $result_laststart = pg_query($pgconn, $sql_laststart);
      echo "Sensor status updated.\n";

      logdb($sensorid, 1);
    } else {
      echo "ERRNO: 99\n";
      echo "ERROR: No static ip configuration on the server.\n";

      logdb($sensorid, 2);
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
