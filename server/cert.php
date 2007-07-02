<?php

####################################
# Certificate Generation Handler   #
# SURFnet IDS                      #
# Version 1.04.05                  #
# 31-05-2007                       #
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
# 1.04.06 Added oidtype when no identifier could be found
# 1.04.05 Added extra check on orgname
# 1.04.04 Fixed bug with sensor numbering
# 1.04.03 Fixed typo in SURFnet SOAP stuff
# 1.04.02 Changed identifier check order
# 1.04.01 Organisation identifiers, removed access header
# 1.03.01 Released as part of the 1.03 package
# 1.02.03 Added some more input checks
# 1.02.02 pg_escape_string added to the input variables
# 1.02.01 Initial release
####################################

# Include configuration, connection information and soapcall.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$err =0;

$allowed_get = array(
                "ip_localip",
                "int_vlanid",
		"md5_ris"
);
$check = extractvars($_GET, $allowed_get);
#debug_input();

# Get remoteip and the querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];
$remotehost = $_SERVER['REMOTE_HOST'];

# Check if localip is set.
if (isset($clean['localip'])) {
  $localip = $clean['localip'];
} else {
  $err = 1;
  echo "ERROR: Localip was empty.<br />\n";
}

# Check if vlanid is set.
if (isset($clean['vlanid'])) {
  $vlanid = $clean['vlanid'];
} else {
  $err = 1;
  echo "ERROR: vlanid was empty.<br />\n";
}

if ($err == 0) {
  
  # Check for is_called
  $sql_iscalled = "SELECT is_called FROM sensors_id_seq";
  $result_iscalled = pg_query($pgconn, $sql_iscalled);
  $iscalled_row = pg_fetch_assoc($result_iscalled);
  $iscalled = $iscalled_row['is_called'];

  # Select all records in the table Sensors.
  $sql_sensors = "SELECT last_value FROM sensors_id_seq";
  $result_sensors = pg_query($pgconn, $sql_sensors);
  # Check for the total amount of sensors in the table.
  $total_sensors = pg_fetch_row($result_sensors);

  if ($iscalled != "f") {
    # Add 1 to the total amount of sensors.
    $new_sensor_nr = $total_sensors[0] + 1;
  } else {
    $new_sensor_nr = $total_sensors[0];
  }

  # The new sensor will be given a name.
  $keyname = "sensor" . $new_sensor_nr;

  # Starting organisation identifier stuff
  $orgname = "false";
  $orgid = 0;

  # Random Identifier String check
  if ($orgid == 0 && isset($clean['ris'])) {
    $ident = $clean['ris'];
    $orgid = checkident($ident, 1);
  }

  if ($c_certsoapconn == 1) {
    # SURFnet SOAP identifier check
    $ident = getorg($remoteip, $c_soapurl, $c_soapuser, $c_soappass);
    if ($ident != "false") {
      $orgid = checkident($ident, 4);
      $orgname = $ident;
      $oidtype = 4;
    } else {
      $orgid = 0;
    }
  }

  # Domain identifier check
  if ($remoteip != $remotehost && $orgid == 0) {
    $ident = getdomain($remotehost);
    if ($ident != "false") {
      $orgid = checkident($ident, 3);
      $orgname = $ident;
      $oidtype = 3;
    } else {
      $orgid = 0;
    }
  }

  # WHOIS identifier check
  if ($orgid == 0) {
    $ident = chkwhois($remoteip);
    if ($ident != "false") {
      $orgid = checkident($ident, 2);
      $orgname = $ident;
      $oidtype = 2;
    } else {
      $orgid = 0;
    }
  }

  if ($orgid == 0) {
    # Organisation did not exist yet.
    if ($orgname == "false" || $orgname == "") {
      $orgname = $remoteip;
      $oidtype = 0;
    }
    $ranges = "";
     
    $sql_chkorg = "SELECT id FROM organisations WHERE organisation = '$orgname'";
    $result_chkorg = pg_query($pgconn, $sql_chkorg);
    $numchk = pg_num_rows($result_chkorg);
    if ($numchk == 0) {
      $sql_addorg = "INSERT INTO organisations (organisation, ranges) VALUES ('$orgname', '$ranges')";
      $result_addorg = pg_query($pgconn, $sql_addorg);

      $sql_getorgid = "SELECT id FROM organisations WHERE organisation = '" .$orgname. "'";
      $result_getorgid = pg_query($pgconn, $sql_getorgid);
      $orgid = pg_result($result_getorgid, 0);
    } else {
      $orgid = pg_result($result_chkorg, 0);
    }

    $sql_addoid = "INSERT INTO org_id (orgid, identifier, type) VALUES ($orgid, '$orgname', $oidtype)";
    $result_addoid = pg_query($pgconn, $sql_addoid);
  }

  # Update the database with Keyname, Remoteip, Localip and Organisation.
  $sql_addsensor = "INSERT INTO sensors (keyname, remoteip, localip, organisation, vlanid) VALUES ('$keyname', '$remoteip', '$localip', $orgid, $vlanid)";
  $result_addsensor = pg_query($pgconn, $sql_addsensor);

  # Start the scripts to generate and sign the certificates for the sensor.
  shell_exec("$c_genkeysdir/generate_certificate.sh $keyname");
  shell_exec("$c_genkeysdir/sign_certificate.sh $keyname");

  ##########################
  #  Print the .key file   #
  ##########################

  # The .key file is created by earlier shellscripts. Open it and print it.
  $key="$c_keysdir/$keyname" . ".key";

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
  $crt="$c_keysdir/$keyname" . ".crt";

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
