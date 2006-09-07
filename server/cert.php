<?php

####################################
# Certificate Generation Handler   #
# SURFnet IDS                      #
# Version 1.02.03                  #
# 26-07-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

# Called by the startclient script on the sensor. This script is used to generate and download the certificates needed by the sensor.
# When startclient on the sensor is run and the sensor does not have sensor certificates yet, this script will be called.
# The certificates will be generated and send back to the sensor in the form of this php page.

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

####################################
# Changelog:
# 1.02.03 Added some more input checks
# 1.02.02 Added identifier column to organisations table
# 1.02.01 Initial release
####################################

# Include configuration, connection information and soapcall.
include('include/certconf.inc.php');
include('include/connect.inc.php');
include('include/functions.inc.php');

# Get remoteip and the querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];
$remotehost = $_SERVER['REMOTE_HOST'];

# Check if localip is set.
if (isset($_GET['localip'])) {
  $localip = stripinput($_GET['localip']);
} else {
  $localip = "";
  echo "ERROR: Localip was empty.<br />\n";
}

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
#  echo "ERROR: Wrong header info.<br />\n";
#}
# Check if $localip is not an empty variable.
#elseif ($localip != "") {
if ($localip != "") {
  # Select all records in the table Sensors.
  $sql_sensors = "SELECT last_value FROM sensors_id_seq";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  # Check for the total amount of sensors in the table.
  $total_sensors = pg_fetch_row($result_sensors);
  # Add 1 to the total amount of sensors.
  $new_sensor_nr = $total_sensors[0] + 1;

  # The new sensor will be given a name.
  $keyname = "sensor" . $new_sensor_nr;

  # Retrieve the organisation name.
  if ($certsoapconn == 1) {
    $org = getOrg($remoteip, $soapurl, $soapuser, $soappass);
  }
  else {
    $org = getDomain($remotehost);
  }

  # If the organisation does not exist yet, add a new one.
  $sql_checkorg = "SELECT id FROM org_id WHERE identifier = '" .$org. "'";
  $result_checkorg = pg_query($pgconn, $sql_checkorg);
  $numrows_checkorg = pg_num_rows($result_checkorg);
  if ($numrows_checkorg == 0) {
    $ranges = "";
    if ($certsoapconn == 1) {
      $ranges =  getorgif($org, $soapurl, $soapuser, $soappass);
    }

    $sql_addorg = "INSERT INTO organisations (organisation, ranges) VALUES ('$org', '$ranges')";
    $result_addorg = pg_query($pgconn, $sql_addorg);

    # Get the organisation id.
    $sql_getorgid = "SELECT id FROM org_id WHERE identifier = '" .$org. "'";
    $result_getorgid = pg_query($pgconn, $sql_getorgid);
    $orgid = pg_result($result_getorgid, 0);

    $sql_addorg = "INSERT INTO org_id (identifier, orgid) VALUES ('$org', $orgid)";
    $result_addorg = pg_query($pgconn, $sql_addorg);
  }
  else {
    # Get the organisation id.
    $sql_getorgid = "SELECT id FROM org_id WHERE identifier = '" .$org. "'";
    $result_getorgid = pg_query($pgconn, $sql_getorgid);
    $orgid = pg_result($result_getorgid, 0);
  }

  # Update the database with Keyname, Remoteip, Localip and Organisation.
  $sql_addsensor = "INSERT INTO sensors (keyname, remoteip, localip, organisation) VALUES ('$keyname', '$remoteip', '$localip', $orgid)";
  $result_addsensor = pg_query($pgconn, $sql_addsensor);

  # Start the scripts to generate and sign the certificates for the sensor.
  shell_exec("$genkeysdir/generate_certificate.sh $keyname");
  shell_exec("$genkeysdir/sign_certificate.sh $keyname");

  ##########################
  #  Print the .key file   #
  ##########################

  # The .key file is created by earlier shellscripts. Open it and print it.
  $key="$keysdir/$keyname" . ".key";

  $keyfile = fopen("$key","r");
  if (filesize("$key")>0) {
    # Print the .key file.
    readfile($key);
  }
  fclose($keyfile);
  # Print an EOF. This helps the sensor to parse cert.php and extract the .key file.
  echo "EOF\n";

  ##########################
  #  Print the .crt file   #
  ##########################

  # The .crt file is created by earlier shellscripts. Open it and print it.
  $crt="$keysdir/$keyname" . ".crt";

  $crtfile = fopen("$crt","r");
  if (filesize("$crt")>0) {
    # Print the .crt file.
    readfile($crt);
  }
  fclose($crtfile);
  # Print the keyname. The sensor will need this to save the .crt and .key file correctly.
  echo "EOF\n";
  echo "$keyname\n";
} 
# Close the link the the database.
pg_close($pgconn);
?>
