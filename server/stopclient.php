<?php

####################################
# Stopclient info update           #
# SURFnet IDS                      #
# Version 1.03.01                  #
# 11-10-2006                       #
# Jan van Lith & Kees Trippelvitz  #
# Modified by Peter Arts           #
####################################

# Called by the stopclient script on the sensor. This script is used to exchange information from and to the sensor when the stopclient script
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

#####################
# Changelog:
# 1.03.01 Released as part of the 1.03 package
# 1.02.02 Added some more input checks
# 1.02.01 Initial release
#####################

# Include configuration and connection information.
include('include/certconf.inc.php');
include('include/connect.inc.php');
include('include/functions.inc.php');

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
# Database #
############
$sql_sensors = "SELECT * FROM sensors WHERE keyname = '$keyname'";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {
  echo "ERRNO: 93\n";
  echo "ERROR: No record in the database for sensor: $keyname\n";
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

  echo "############-SERVER-INFO-##########\n";
  echo "TIMESTAMP: $date_string\n";
  echo "ACTION: $action\n";
  echo "SSH: $ssh\n";
  echo "STATUS: $status\n";
  echo "SERVER: $server\n";
  echo "TAPIP: $tapip\n";
  echo "SERVERCONF: $serverconf\n";
  echo "NEWUPTIME: $newuptime\n";
  echo "############-CLIENT-INFO-##########\n";
  echo "REMOTEIP: $remoteip\n";
  echo "KEYNAME: $keyname\n";
  echo "CLIENTCONF: $clientconf\n";

  echo "#######-Taken actions-#######\n";

  # If remoteip has changed, update it to the database.
  if ($row['remoteip'] != $remoteip) {
    echo "Updated remote IP address.\n";
    $sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname'";
    $result_update_remote = pg_query($pgconn, $sql_update_remote);
  }

  # If localip has changed, update it to the database.
  if ($row['localip'] != $localip) {
    echo "Updated local IP address.\n";
    $sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname'";
    $result_update = pg_query($pgconn, $sql_update);
  }

  # Update the last start timestamp to the database.
  $sql_laststart = "UPDATE sensors SET status = 0, uptime = $newuptime, laststop = '$date' WHERE keyname = '$keyname'";
  $result_laststart = pg_query($pgconn, $sql_laststart);
}

# Close the connection with the database.
pg_close($pgconn);
?>
