<?php

####################################
# Status info                      #
# SURFids 2.04                     #
# Changeset 005                    #
# 08-04-2008                       #
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
                "int_ssh",
                "int_vlanid",
		"int_rev",
		"strip_html_escape_version",
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

###########
# localip #
###########
if (isset($clean['mac'])) {
  $mac = $clean['mac'];
} else {
  $mac = "";
}

############
# checkssh #
############
if (isset($clean['ssh'])) {
  $checkssh = $clean['ssh'];
  if ($checkssh > 0) {
    $checkssh = 1;
  }
} else {
  $err = 93;
  echo "ERRNO: $err\n";
  echo "ERROR: Invalid or missing SSH variable!\n";
  $err = 1;
}

############
# revision #
############
if (isset($clean['rev'])) {
  $rev = $clean['rev'];
} else {
  $rev = 0;
}

############
# version  #
############
if (isset($clean['version'])) {
  $version = $clean['version'];
} else {
  $version = "";
}

###########
# vlanid  #
###########
if (isset($clean['vlanid'])) {
  $vlanid = $clean['vlanid'];
} else {
  $err = 94;
  echo "ERRNO: $err\n";
  echo "ERROR: Invalid or missing VLAN ID!\n";
}

############
# Database #
############
if ($err == 0) {
  $sql_sensors = "SELECT action, ssh, status, laststart, uptime, tapip, netconf, tap, id, rev, localip, remoteip, sensormac";
  $sql_sensors .= " FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  $numrows = pg_num_rows($result_sensors);
  if ($numrows == 0) {
    $err = 95;
    echo "ERRNO: $err\n";
    echo "ERROR: Could not find database record!\n";
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
  $tap = $row['tap'];
  $tapip = $row['tapip'];
  $db_localip = $row['localip'];
  $db_remoteip = $row['remoteip'];
  $db_mac = $row['sensormac'];
  $serverconf = $row['netconf'];
  $newuptime = $uptime + ($date - $laststart);
  $oldrev = $row['rev'];

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
  echo "SERVERCONF: $serverconf\n";
  echo "VLANID: $vlanid\n";
  echo "NEWUPTIME: $newuptime\n";
  echo "REVISION: $oldrev\n";
  echo "SENSORMAC: $db_mac\n";
  echo "############-CLIENT-INFO-##########\n";
  echo "REMOTEIP: $remoteip\n";
  echo "KEYNAME: $keyname\n";
  echo "CLIENTSSH: $checkssh\n";
  echo "REVISION: $rev\n";
  echo "LOCALIP: $localip\n";
  echo "REMOTEIP: $remoteip\n";
  echo "SENSORMAC: $mac\n";

  echo "#######-Action log-#######\n";
  if ($checkssh != $ssh) {
    $sql_checkssh = "UPDATE sensors SET ssh = $checkssh WHERE keyname = '$keyname'";
    $result_checkssh = pg_query($pgconn, $sql_checkssh);
    echo "[Database] SSH update!\n";
  }

  if ($rev != 0) {
    if ($rev > $oldrev) {
      $sql_rev = "UPDATE sensors SET rev = '$rev' WHERE keyname = '$keyname'";
      $result_rev = pg_query($pgconn, $sql_rev);
      echo "[Database] Revision update!\n";
      logdb($keyname, 17, $rev);
    }
  }

  if ($version != "") {
    $sql_version = "UPDATE sensors SET version = '$version' WHERE keyname = '$keyname'";
    $result_version = pg_query($pgconn, $sql_version);
    echo "[Database] Version update!\n";
  }

  if ($mac != "") {
    if ($mac != $db_mac) {
      $sql_mac = "UPDATE sensors SET sensormac = '$mac' WHERE keyname = '$keyname'";
      $result_mac = pg_query($pgconn, $sql_mac);
      echo "[Database] MAC address update!\n";
    }
  }

#  if ($remoteip != "") {
#    $sql_rip = "UPDATE sensors SET remoteip = '$remoteip' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
#    $result_rip = pg_query($pgconn, $sql_rip);
#    echo "[Database] Remoteip update!\n";
#  }

  if ($db_localip != $localip) {
    $sql_lip = "UPDATE sensors SET localip = '$localip' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_lip = pg_query($pgconn, $sql_lip);
    echo "[Database] Localip update!\n";
    logdb($sensorid, 13);
  }

  if ($tap != "" && $status == 1) {
    $sql_lastupdate = "UPDATE sensors SET lastupdate = '$date' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_lastupdate = pg_query($pgconn, $sql_lastupdate);
    echo "[Database] Uptime update!\n";
  }
  if ($action == "SSHOFF") {
    $sql_ssh = "UPDATE sensors SET ssh = 0 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "[Sensor] Disabled SSH!\n";

    logdb($sensorid, 4);
  } elseif ($action == "SSHON") {
    $sql_ssh = "UPDATE sensors SET ssh = 1 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "[Sensor] Enabled SSH!\n";

    logdb($sensorid, 5);
  } elseif ($action == "UNBLOCK") {
    $sql_block = "UPDATE sensors SET status = 0 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "[Sensor] Enabled client!\n";

    logdb($sensorid, 6);
  } elseif ($action == "BLOCK") {
    $sql_block = "UPDATE sensors SET status = 2 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "[Sensor] Disabled client!\n"; 

    logdb($sensorid, 7);
  } elseif ($action == "REBOOT") {
    logdb($sensorid, 8);
  }
  $sql_action = "UPDATE sensors SET action = 'NONE' WHERE keyname = '$keyname'";
  $result_action = pg_query($pgconn, $sql_action);
  echo "[Database] Action command reset!\n";
}

# Close the connection with the database.
pg_close($pgconn);
?>
