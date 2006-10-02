<?php

#####################################
# Information check for the sensors #
# SURFnet IDS                       #
# Version 1.02.03                   #
# 27-07-2006                        #
# Jan van Lith & Kees Trippelvitz   #
#                                   #
# Obsolete in version 1.02          #
#                                   #
# Kept for backwards compatability  #
# when upgrading                    #
#####################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
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

#############################################
# Changelog:
# 1.02.03 Added some more input checks
# 1.02.02 Added pg_escape_string to the $_GET variables
# 1.02.01 Initial release
#############################################

# Include configuration and connection information.
include('include/certconf.inc.php');
include('include/connect.inc.php');
include('include/functions.inc.php');

# Get remoteip and querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];
echo "Remoteip: $remoteip<br />\n";

if (isset($_GET['keyname']) && isset($_GET['update'])) {
  $keyname = stripinput(pg_escape_string($_GET['keyname']));
  $update = intval($_GET['update']);
  
  # Check if there is an existing record with $keyname.
  $sql_sensors = "SELECT localip, remoteip, reboot FROM sensors WHERE keyname = '$keyname'";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  $row = pg_fetch_row($result_sensors);
  $reboot = $row[2];
  if ($reboot == 1) {
    $sql_reboot = "UPDATE sensors SET reboot = 0 WHERE keyname = '$keyname'";
    $result_reboot = pg_query($pgconn, $sql_reboot);
    echo "REBOOT";
  }
  
  # If remoteip has changed, update it to the database.
  if ($row[1] != $remoteip) {
    $sql_update_remote = "UPDATE sensors SET remoteip = '" .$remoteip. "' WHERE keyname = '$keyname'";
    $result_update_remote = pg_query($pgconn, $sql_update_remote);
  }

  # Update the database with the time of this update.
  $date = time();
  if ($update == 1) {
    $sql_lastupdate = "UPDATE sensors SET lastupdate = '$date' WHERE keyname = '$keyname'";
    $result_lastupdate = pg_query($pgconn, $sql_lastupdate);
  }
  elseif ($update == 0 && isset($_GET['localip'])) {
    # If the sensorip in the database is old, then update.
    $localip = stripinput(pg_escape_string($_GET['localip']));
    echo "Localip: $localip<br />\n";
    if ($row[0] != $localip) {
      # Update the database with the new $localip and $remoteip.
      $sql_update = "UPDATE sensors SET localip = '" .$localip. "' WHERE keyname = '$keyname'";
      echo "SQL_UPDATE: $sql_update<br />\n";
      $result_update = pg_query($pgconn, $sql_update);
    }
    
    # Update the last start timestamp to the database.
    $sql_laststart = "UPDATE Sensors SET Laststart = '$date' WHERE Keyname = '$keyname'";
    $result_laststart = pg_query($pgconn, $sql_laststart);
  }
  else {
    echo "ERROR: Wrong update number or missing localip.\n";
  }
}
else {
  echo "ERROR: Localip, keyname or update variable not set.\n";
}

# Close the connection with the database.
pg_close($pgconn);
?>
