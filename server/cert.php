<?php

####################################
# Certificate Generation Handler   #
# SURFids 3.00                     #
# Changeset 002                    #
# 18-02-2009                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

################################################################################
# Called by the startclient script on the sensor. This script is used to 
# generate and download the certificates needed by the sensor. When startclient 
# on the sensor is run and the sensor does not have sensor certificates yet, this 
# script will be called. The certificates will be generated and send back to the 
# sensor in the form of this php page.
################################################################################

####################################
# Changelog:
# 002 Added extensive logging via logsys
# 001 Changed the order of organisation checks
####################################

# Include configuration, connection information and soapcall.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$err =0;

$allowed_get = array(
                "ip_localip",
        		"md5_oid"
);
$check = extractvars($_GET, $allowed_get);
#debug_input();

# Get remoteip and the querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];
$remotehost = $_SERVER['REMOTE_HOST'];

logsys($f_log_warn, "CERT_NEW", "Host ($remoteip) is requesting a new certificate");

# Check if localip is set.
if (isset($clean['localip'])) {
  $localip = $clean['localip'];
} else {
  $err = 1;
  echo "ERROR: Localip was empty.\n";
  logsys($f_log_error, "CERT_FAIL", "Localip was empty");
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
  $soap_org = "";
  $domain_org = "";
  $whois_org = "";

  # Random Identifier String check
  if ($orgid == 0 && isset($clean['oid'])) {
    $ident = $clean['oid'];
    $orgid = checkident($ident, 1);
  }

  if ($orgid == 0) {
    if ($c_certsoapconn == 1) {
      # SURFnet SOAP identifier check
      $ident = getorg($remoteip, $c_soapurl, $c_soapuser, $c_soappass);
      $soap_org = $ident;
      if ($ident != "false") {
        $orgid = checkident($ident, 4);
        $orgname = $ident;
        $oidtype = 4;
      } else {
        $orgid = 0;
      }
    }
  }

  # Domain identifier check
  if ($remoteip != $remotehost && $orgid == 0 && $remotehost != "") {
    $ident = getdomain($remotehost);
    $domain_org = $ident;
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
    $whois_org = $ident;
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

    if ($soap_org != "" && $soap_org != "false") {
      $orgname = $soap_org;
      $oidtype = 4;
    } elseif ($domain_org != "" && $domain_org != "false") {
      $orgname = $domain_org;
      $oidtype = 3;
    } elseif ($whois_org != "" && $whois_org != "false") {
      $orgname = $whois_org;
      $oidtype = 2;
    } else {  
      $orgname = $remoteip;
      $oidtype = 0;
    }
    $ranges = "";

    $sql_chkorg = "SELECT id FROM organisations WHERE organisation = '$orgname'";
    $result_chkorg = pg_query($pgconn, $sql_chkorg);
    $numchk = pg_num_rows($result_chkorg);
    if ($numchk == 0) {

      logsys($f_log_debug, "CERT_INFO", "Adding new organisation ($orgname)");

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

  # Update the database with Keyname, Organisation and vlanid.
  $sql_addsensor = "INSERT INTO sensors (keyname, organisation, vlanid) VALUES ('$keyname', $orgid, 0)";
  $result_addsensor = pg_query($pgconn, $sql_addsensor);

  # Update the database with the remoteip and localip
  $sql_addsensor = "INSERT INTO sensor_details (keyname, remoteip, localip) VALUES ('$keyname', '$remoteip', '$localip')";
  $result_addsensor = pg_query($pgconn, $sql_addsensor);

  # Start the scripts to generate and sign the certificates for the sensor.
  exec("$c_genkeysdir/generate_certificate.sh $keyname 2>&1", $output, $rv);
  if ($rv != 0) {
    foreach ($output as $key => $val) {
      if (stripos($val, "error")) {
        logsys($f_log_error, "EXEC_FAIL", "[$key] $val");
      }
    }
  }
  $output = "";
  $rv = "";
  exec("$c_genkeysdir/sign_certificate.sh $keyname 2>&1", $output, $rv);
  if ($rv != 0) {
    foreach ($output as $key => $val) {
      logsys($f_log_error, "EXEC_FAIL", "[$key] $val");
    }
  }

  ##########################
  #  Print the .key file   #
  ##########################

  # The .key file is created by earlier shellscripts. Open it and print it.
  $key="$c_keysdir/$keyname" . ".key";

  if (file_exists($key)) {
      $keyfile = fopen("$key","r");
      if (filesize("$key")>0) {
          # Print the .key file.
          readfile($key);
      }
      fclose($keyfile);
  } else {
    logsys($f_log_error, "EXEC_FAIL", "Key file did not exist ($key)");
  }
  # Print an EOF. This helps the sensor to parse cert.php and extract the .key file.
  echo "EOF\n";

  ##########################
  #  Print the .crt file   #
  ##########################

  # The .crt file is created by earlier shellscripts. Open it and print it.
  $crt="$c_keysdir/$keyname" . ".crt";

  if (file_exists($crt)) {
      $crtfile = fopen("$crt","r");
      if (filesize("$crt")>0) {
          # Print the .crt file.
          readfile($crt);
      }
      fclose($crtfile);
  } else {
    logsys($f_log_error, "EXEC_FAIL", "Cert file did not exist ($crt)");
  }
  # Print the keyname. The sensor will need this to save the .crt and .key file correctly.
  echo "EOF\n";
  echo "$keyname\n";
} 
# Close the link the the database.
pg_close($pgconn);
?>
