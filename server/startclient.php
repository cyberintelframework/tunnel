<?php

####################################
# Startclient info update          #
# SURFnet IDS                      #
# Version 1.02.02                  #
# 26-07-2006                       #
# Jan van Lith & Kees Trippelvitz  #
# Modified by Peter Arts           #
####################################

# Called by the startclient script on the sensor. This script is used to exchange information from and to the sensor when the startclient script
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
# 1.04.02 VLAN support
# 1.04.01 Released as 1.04.01
# 1.03.01 Released as part of the 1.03 package
# 1.02.03 Added some more input checks
# 1.02.02 pg_escape_string added to the input variables
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
# ifmethod #
############
if ( isset($_GET['ifmethod']) ) {
  $clientconf = stripinput(pg_escape_string($_GET['ifmethod']));
} else {
  echo "ERRNO: 93\n";
  echo "ERROR: Client network config (ifmethod) not present.\n";
  $err = 1;
}

####################
# ifmethod detail  #
####################
if ( isset($_GET['detail']) ) {
  $netconfdetail = stripinput(pg_escape_string($_GET['detail']));
} else {
  echo "ERRNO: 94\n";
  echo "ERROR: Details of ifmethod not present.\n";
  $err = 1;
}
############
# vlan id  #
############
if ( isset($_GET['vlanid']) ) {
  $vlanid = stripinput(pg_escape_string($_GET['vlanid']));
} else {
  echo "ERRNO: 95\n";
  echo "VLAN ID not set.\n";
  $err = 1;
}
############

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
  $action = $row['action'];
  $ssh = $row['ssh'];
  $status = $row['status'];
  $laststart = $row['laststart'];
  $uptime = $row['uptime'];
  $server = $row['server'];
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
  echo "SERVER: $server\n";
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
    $sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname' AND vlanid='$vlanid'";
    $result_update_remote = pg_query($pgconn, $sql_update_remote);
  }
  
  # If localip has changed, update it to the database.
  if ($row['localip'] != $localip) {
    echo "Updated local IP address.\n";
    $sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname' AND vlanid='$vlanid'";
    $result_update = pg_query($pgconn, $sql_update);
  }
  
  # Setting network config in the database
  $sql_netconf = "UPDATE sensors SET netconf = '$clientconf', netconfdetail = '$netconfdetail' WHERE keyname = '$keyname' and vlanid='$vlanid'";
  $result_netconf = pg_query($pgconn, $sql_netconf);
  echo "Network config updated.\n";

  # Set status 
  if ($clientconf == "dhcp" | $clientconf == "vland") {
      $sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1, tapip = NULL WHERE keyname = '$keyname' and vlanid='$vlanid'";
      $result_laststart = pg_query($pgconn, $sql_laststart);
      echo "Sensor status updated.\n";
  } else {
    if ($tapip != "NULL") {
      $sql_laststart = "UPDATE sensors SET laststart = '$date', status = 1 WHERE keyname = '$keyname' AND vlanid='$vlanid'";
      $result_laststart = pg_query($pgconn, $sql_laststart);
      echo "Sensor status updated.\n";
    } else {
      echo "ERRNO: 99\n";
      echo "ERROR: No static ip configuration on the server.\n";
    }
  }
}

# Close the connection with the database.
pg_close($pgconn);
?>
