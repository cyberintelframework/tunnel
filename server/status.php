<?php

####################################
# Status info                      #
# SURFnet IDS                      #
# Version 1.04.02                  #
# 26-03-2007                       #
# Jan van Lith & Kees Trippelvitz  #
# Modified by Peter Arts           #
####################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
# Modified by Peter Arts                                                                #
#                                                                                       #
# This program is free software; you can redistribute it and/or                         #
# modify it under the terms of the GNU General Public License                           #
# as published by the Free Software Foundation; either version 2                        #
# of the License, or (at your option) any later version.                                #
#                                                                                       #
# This program is distributed in the hope that it will be useful,                       #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                        #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                         #
# GNU General Public License for more details.                                          #
#                                                                                       #
# You should have received a copy of the GNU General Public License                     #
# along with this program; if not, write to the Free Software                           #
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.       #
#                                                                                       #
# Contact ids@surfnet.nl                                                                #
#########################################################################################

####################################
# Changelog:
# 1.04.02 Added remoteip and localip updates
# 1.04.01 Initial release
####################################

# Include configuration and connection information
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$err = 0;

# Get remoteip
$remoteip = $_SERVER['REMOTE_ADDR'];

$allowed_get = array(
                "sensor",
                "ip_localip",
                "int_ssh",
                "int_vlanid"
);
$check = extractvars($_GET, $allowed_get);
debug_input();

###########
# Keyname #
###########
if (isset($tainted['sensor'])) {
  $chkkey = $tainted['sensor'];
  $pattern = '/^sensor[0-9]+$/';
  if (!preg_match($pattern, $chkkey)) {
    $err = 91;
    echo "ERRNO: $err\n";
    echo "ERROR: Invalid or missing sensor name!\n";
  } else {
    $keyname = $tainted['sensor'];
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
  $sql_sensors = "SELECT action, ssh, status, laststart, uptime, server, tapip, netconf, tap";
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
  $action = $row['action'];
  $ssh = $row['ssh'];
  $status = $row['status'];
  $laststart = $row['laststart'];
  $uptime = $row['uptime'];
  $server = $row['server'];
  $tapip = $row['tapip'];
  $serverconf = $row['netconf'];
  $newuptime = $uptime + ($date - $laststart);

  $sql_server = "SELECT server FROM servers WHERE id = $server";
  $result_server = pg_query($pgconn, $sql_server);
  $row = pg_fetch_assoc($result_server);
  $server = $row['server'];

  if ($action == "") {
    $action = "NONE";
  }

  echo "############-SERVER-INFO-##########\n";
  echo "TIMESTAMP: $date_string\n";
  echo "ACTION: $action\n";
  echo "SERVERSSH: $ssh\n";
  echo "STATUS: $status\n";
  echo "SERVER: $server\n";
  echo "TAPIP: $tapip\n";
  echo "SERVERCONF: $serverconf\n";
  echo "VLANID: $vlanid\n";
  echo "NEWUPTIME: $newuptime\n";
  echo "############-CLIENT-INFO-##########\n";
  echo "REMOTEIP: $remoteip\n";
  echo "KEYNAME: $keyname\n";
  echo "CLIENTSSH: $checkssh\n";

  echo "#######-Action log-#######\n";
  if ($checkssh != $ssh) {
    $sql_checkssh = "UPDATE sensors SET ssh = $checkssh WHERE keyname = '$keyname'";
    $result_checkssh = pg_query($pgconn, $sql_checkssh);
    echo "[Database] SSH update!\n";
  }

  if ($remoteip != "") {
    $sql_rip = "UPDATE sensors SET remoteip = '$remoteip' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_rip = pg_query($pgconn, $sql_rip);
    echo "[Database] Remoteip update!\n";
  }

  $sql_lip = "UPDATE sensors SET localip = '$localip' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_lip = pg_query($pgconn, $sql_lip);
  echo "[Database] Localip update!\n";

  if ($tap != "" && $status == 1) {
    $sql_lastupdate = "UPDATE sensors SET lastupdate = '$date' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
    $result_lastupdate = pg_query($pgconn, $sql_lastupdate);
    echo "[Database] Uptime update!\n";
  }
  if ($action == "SSHOFF") {
    $sql_ssh = "UPDATE sensors SET ssh = 0 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "[Sensor] Disabled SSH!\n";
  } elseif ($action == "SSHON") {
    $sql_ssh = "UPDATE sensors SET ssh = 1 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "[Sensor] Enabled SSH!\n";
  }
  if ($action == "UNBLOCK") {
    $sql_block = "UPDATE sensors SET status = 0 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "[Sensor] Enabled client!\n";
  } elseif ($action == "BLOCK") {
    $sql_block = "UPDATE sensors SET status = 2 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "[Sensor] Disabled client!\n"; 
  }
  $sql_action = "UPDATE sensors SET action = 'NONE' WHERE keyname = '$keyname'";
  $result_action = pg_query($pgconn, $sql_action);
  echo "[Database] Action command reset!\n";
}

# Close the connection with the database.
pg_close($pgconn);
?>
