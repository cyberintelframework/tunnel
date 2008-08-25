<?php

####################################
# Status info                      #
# SURFids 2.10.00                  #
# Changeset 006                    #
# 25-08-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
####################################

####################################
# Changelog:
# 006 OS version check
# 005 Changed logdb for rev change
# 004 Removed $server variable stuff
# 003 Fixed localip bug, added MAC address stuff
# 002 Added revision and version support
# 001 version 2.10.00
####################################

# Include configuration and connection information
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$err = 0;

# Get remoteip
$remoteip = $_SERVER['REMOTE_ADDR'];
$prefix = "status.php";

$allowed_get = array(
                "strip_html_escape_keyname",
                "ip_localip",
                "int_ssh",
                "int_vlanid",
		"int_rev",
		"strip_html_escape_version",
		"strip_html_escape_knoppixv",
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
    logdb($prefix, 3, "NO_KEYNAME_GIVEN", $sensorid, $remoteip);
  } else {
    $keyname = $clean['keyname'];
  }
} else {
  $err = 91;
  echo "ERRNO: $err\n";
  echo "ERROR: Invalid or missing sensor name!\n";
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
  logdb($prefix, 3, "NO_VLANID_GIVEN", $sensorid, $remoteip);
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
  $err = 92;
  echo "ERRNO: $err\n";
  echo "ERROR: Invalid or missing local IP address!\n";
  logdb($prefix, 3, "NO_LOCALIP_GIVEN", $sensorid, $remoteip);
}

###########
# MAC     #
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
  logdb($prefix, 3, "NO_SSH_GIVEN", $sensorid, $remoteip);
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

############
# version  #
############
if (isset($clean['knoppixv'])) {
  $knoppixv = $clean['knoppixv'];
} else {
  $knoppixv = 0;
}

############
# Database #
############
if ($err == 0) {
  $sql_sensors = "SELECT action, ssh, status, laststart, uptime, tapip, netconf, tap, id, rev, localip, remoteip, sensormac, version, osv ";
  $sql_sensors .= " FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  $numrows = pg_num_rows($result_sensors);
  if ($numrows == 0) {
    $err = 95;
    echo "ERRNO: $err\n";
    echo "ERROR: Could not find database record!\n";
    logdb($prefix, 3, "NO_SENSOR_FOUND", $sensorid, $remoteip);
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
  $db_version = $row['version'];
  $serverconf = $row['netconf'];
  $newuptime = $uptime + ($date - $laststart);
  $oldrev = $row['rev'];
  $db_knoppixv = $row['osv'];

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
  echo "KNOPPIXV: $db_knoppixv\n";
  echo "############-CLIENT-INFO-##########\n";
  echo "REMOTEIP: $remoteip\n";
  echo "KEYNAME: $keyname\n";
  echo "CLIENTSSH: $checkssh\n";
  echo "REVISION: $rev\n";
  echo "LOCALIP: $localip\n";
  echo "REMOTEIP: $remoteip\n";
  echo "SENSORMAC: $mac\n";
  echo "KNOPPIXV: $knoppixv\n";

  echo "#######-Action log-#######\n";
  if ($checkssh != $ssh) {
    $sql_checkssh = "UPDATE sensors SET ssh = $checkssh WHERE keyname = '$keyname'";
    $result_checkssh = pg_query($pgconn, $sql_checkssh);
    echo "[Database] SSH update!\n";
    logdb($prefix, 0, "DB_UPDATE_SSH", $sensorid, "$checkssh, $ssh");
  }

  if ($knoppixv != $db_knoppixv) {
    $sql_osv = "UPDATE sensors SET osv = '$knoppixv' WHERE keyname = '$keyname'";
    $result_osv = pg_query($pgconn, $sql_osv);
    echo "[Database] OS version update!\n";
    logdb($prefix, 0, "DB_UPDATE_OSV", $sensorid, "$knoppixv, $db_knoppixv");
  }

  if ($rev != 0) {
    if ($rev > $oldrev) {
      $sql_rev = "UPDATE sensors SET rev = '$rev' WHERE keyname = '$keyname'";
      $result_rev = pg_query($pgconn, $sql_rev);
      echo "[Database] Revision update!\n";
      logdb($prefix, 0, "DB_UPDATE_REV", $sensorid, "$rev, $oldrev");
    }
  }

  if ($version != "") {
    if ($version != $db_version) {
      $sql_version = "UPDATE sensors SET version = '$version' WHERE keyname = '$keyname'";
      $result_version = pg_query($pgconn, $sql_version);
      logdb($prefix, 0, "DB_UPDATE_VERSION", $sensorid);
      echo "[Database] Version update!\n";
    }
  }

  if ($mac != "") {
    $mac = strtolower($mac);
    $db_mac = strtolower($db_mac);
    if ($mac != $db_mac) {
      $sql_mac = "UPDATE sensors SET sensormac = '$mac' WHERE keyname = '$keyname'";
      $result_mac = pg_query($pgconn, $sql_mac);
      logdb($prefix, 0, "DB_UPDATE_MAC", $sensorid, "$mac, $db_mac");
      echo "[Database] MAC address update!\n";
    }
  }

  if ($db_localip != $localip) {
    $sql_lip = "UPDATE sensors SET localip = '$localip' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_lip = pg_query($pgconn, $sql_lip);
    echo "[Database] Localip update!\n";
    logdb($prefix, 0, "DB_UPDATE_LOCALIP", $sensorid, "$localip, $db_localip");
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
    logdb($prefix, 0, "DB_UPDATE_ACTION", $sensorid, "Disabled SSH");
  } elseif ($action == "SSHON") {
    $sql_ssh = "UPDATE sensors SET ssh = 1 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "[Sensor] Enabled SSH!\n";
    logdb($prefix, 0, "DB_UPDATE_ACTION", $sensorid, "Enabled SSH");
  } elseif ($action == "UNBLOCK") {
    $sql_block = "UPDATE sensors SET status = 0 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "[Sensor] Enabled client!\n";
    logdb($prefix, 0, "DB_UPDATE_ACTION", $sensorid, "Unblocked sensor");
  } elseif ($action == "BLOCK") {
    $sql_block = "UPDATE sensors SET status = 2 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "[Sensor] Disabled client!\n"; 
    logdb($prefix, 0, "DB_UPDATE_ACTION", $sensorid, "Blocked sensor");
  } elseif ($action == "REBOOT") {
    logdb($prefix, 0, "DB_UPDATE_ACTION", $sensorid, "Reboot sensor");
  }
  $sql_action = "UPDATE sensors SET action = 'NONE' WHERE keyname = '$keyname'";
  $result_action = pg_query($pgconn, $sql_action);
  echo "[Database] Action command reset!\n";
}

# Close the connection with the database.
pg_close($pgconn);
?>
