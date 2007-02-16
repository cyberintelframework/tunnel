<?php

####################################
# Update info                      #
# SURFnet IDS                      #
# Version 1.04.02                  #
# 20-11-2006                       #
# Jan van Lith & Kees Trippelvitz  #
# Modified by Peter Arts           #
####################################

# Called by the update script on the sensor. This script is used to exchange information from and to the sensor when the update script
# on the sensor is run.

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
# 1.04.02 Fixed VLAN issues 
# 1.04.01 Released as 1.04.01
# 1.03.01 Released as part of the 1.03 package
# 1.02.04 Changed the check on $checkssh to intval()
# 1.02.03 Added some more input checks
# 1.02.02 Changed the way SSH remote control is handled
# 1.02.01 Initial release
####################################

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

# Get remoteip and querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];

# First check if all the variables are present.
$err = 0;

######################
# Wget Accept header #
######################
#$accept_header = $_SERVER['HTTP_ACCEPT'];
#$search = substr_count($accept_header, ",");
#if ($search > 0) {
#  $accept_header_ar = explode(",", $accept_header);
#  $accept_header = $accept_header_ar[1];
#}
#$sensor_md5 = trim($accept_header);
#$server_md5 = `md5sum $surfidsdir/serverkeys/ca.crt | awk '{print $1}'`;
#$server_md5 = trim($server_md5);

#if ($server_md5 != $sensor_md5) {
#  echo "ERRNO: 90\n";
#  echo "ERROR: Wrong header info.\n";
#  $err = 1;
#}

###########
# Keyname #
###########
if ( isset($_GET['keyname']) ) {
  $keyname = stripinput(pg_escape_string($_GET['keyname']));
} else {
  echo "ERRNO: 91\n";
  echo "ERROR: Keyname not present.\n";
  $err = 1;
}

###########
# localip #
###########
if ( isset($_GET['localip']) ) {
  $localip = stripinput(pg_escape_string($_GET['localip']));
} else {
  echo "ERRNO: 92\n";
  echo "ERROR: Localip not present.\n";
  $err = 1;
}

############
# checkssh #
############
if ( isset($_GET['ssh']) ) {
  $checkssh = stripinput(intval($_GET['ssh']));
  if ($checkssh > 0) {
    $checkssh = 1;
  }
} else {
  echo "ERRNO: 93\n";
  echo "ERROR: Check SSH variable not present.\n";
  $err = 1;
}

###########
# vlanid  #
###########
if ( isset($_GET['vlanid']) ) {
  $vlanid = stripinput(pg_escape_string($_GET['vlanid']));
} else {
#  echo "ERRNO: 94\n";
#  echo "ERROR: Vlanid not present.\n";
#  $err = 1;
  $vlanid = 0;
}

############
# Database #
############
$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {
  echo "ERRNO: 95\n";
  echo "ERROR: No record in the database for sensor: $keyname with vlanid: $vlanid\n";
  $err = 1;
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

  echo "#######-Taken actions-#######\n";
  if ($checkssh != $ssh) {
    $sql_checkssh = "UPDATE sensors SET ssh = $checkssh WHERE keyname = '$keyname'";
    $result_checkssh = pg_query($pgconn, $sql_checkssh);
  }

  $sql_lastupdate = "UPDATE sensors SET lastupdate = '$date' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_lastupdate = pg_query($pgconn, $sql_lastupdate);
  if ($action == "SSHOFF") {
    $sql_ssh = "UPDATE sensors SET ssh = 0 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "Disabled SSH\n";
  } elseif ($action == "SSHON") {
    $sql_ssh = "UPDATE sensors SET ssh = 1 WHERE keyname = '$keyname'";
    $result_ssh = pg_query($pgconn, $sql_ssh);
    echo "Enabled SSH\n";
  }
  if ($action == "UNBLOCK") {
    $sql_block = "UPDATE sensors SET status = 0 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "Enabled client.\n";
  } elseif ($action == "BLOCK") {
    $sql_block = "UPDATE sensors SET status = 2 WHERE keyname = '$keyname'";
    $result_block = pg_query($pgconn, $sql_block);
    echo "Disabled client.\n"; 
  }
  $sql_action = "UPDATE sensors SET action = 'NONE' WHERE keyname = '$keyname' AND vlanid = '$vlanid'";
  $result_action = pg_query($pgconn, $sql_action);
  echo "Action command reset.\n";
}

# Close the connection with the database.
pg_close($pgconn);
?>
