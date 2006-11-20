<?php

####################################
# SURFnet IDS                      #
# Version 1.04.02                  #
# 20-11-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 1.04.02 Added chkwhois function
# 1.04.01 Released as 1.04.01
# 1.03.01 Released as part of the 1.03 package
# 1.02.02 Added the stripinput function
# 1.02.01 Initial release
#####################

function checkident($ident, $type) {
  $type = intval($type);
  $ident = pg_escape_string($ident);
  $sql_checkorg = "SELECT orgid FROM org_id WHERE identifier = '" .$ident. "' AND type = $type";
  $result_checkorg = pg_query($pgconn, $sql_checkorg);
  $numrows_checkorg = pg_num_rows($result_checkorg);
  if ($numrows_checkorg == 0) {
    return 0;
  } else {
    $orgid = pg_result($result_checkorg, 0);
    return $orgid;
  }
}

# Function to check for the existance of a netname record in whois info
function chkwhois($remoteip) {
  $whois_server_ar[] = "arin";
  $whois_server_ar[] = "lacnic";
  $whois_server_ar[] = "apnic";
  $whois_server_ar[] = "afrinic";
  $whois_server_ar[] = "ripe";

  $found = 0;
  foreach ($whois_server_ar as $key => $server) {
    $server = "whois." . $server . ".net";
    $fp = @fsockopen($server,43,&$errno,&$errstr,15);
    fputs($fp,"$remoteip\r\n");
    while(!feof($fp)) {
      $line = fgets($fp,256);
      $pattern = '/^.*netname:.*$/';
      if (preg_match($pattern, $line)) {
        $regel = explode(":", $line);
        $org_ident = trim($regel[1]);
        if ($org_ident != "ERX-NETBLOCK" && $org_ident != "IANA-BLK") {
          $found = 1;
          break;
        } else {
          $org_ident = "";
        }
      }
    }
    if ($found == 1) {
      break;
    }
    fclose($fp);
  }
  if ($found == 0) {
    return "false";
  } else {
    return $org_ident;
  }
}

# Removes certain strings from the input. This is used to prevent XSS attacks.
function stripinput($input) {
  $pattern_ar = array("<script>", "</script>", "<", "</", ">", "%");
  foreach($pattern_ar as $pattern) {
    $input = str_replace($pattern, '', $input);
  }
  return $input;
}

# Returns the domain portion of a FQDN.
function getdomain($host) {
  $count = 0;
  $domain_ar = split("\.", $host);
  $count = count($domain_ar);
  $last = $count - 1;
  if ($domain_ar[$last] == "uk") {
    $tld = $last;
    $uk = $last - 1;
    $domain = $last - 2;
    $domain = $domain_ar[$domain] . "." . $domain_ar[$uk] . "." . $domain_ar[$tld];
  } else {
    $tld = $last;
    $domain = $last - 1;
    $domain = $domain_ar[$domain] . "." . $domain_ar[$tld];
  }
  return $domain;
}

# Function to get the organisation of a connecting sensor.
function getOrg($ip, $soapurl, $soapuser, $soappass) {
  require_once('include/nusoap.php');
  $soap_client = new soapclient($soapurl, true);
  $soap_client->setCredentials($soapuser, $soappass); 
  $soap_err = $soap_client->getError();
  if ($soap_err) {
#    $remotehost = $_SERVER['REMOTE_HOST'];
#    $soap_org = getDomain($remotehost);
    $soap_org = "false";
  } else {
    $remoteip = $ip;
    $soap_klanten = array("var_type" => "ip", "var_value" => "$remoteip", "version" => "1.0");
    $soap_result = $soap_client->call('getKlantSingle', array('invoer' => $soap_klanten));
    $soap_org = $soap_result[klantafkorting];
    if ($soap_org == "") {
      $remotehost = $_SERVER['REMOTE_HOST'];
      $soap_org = getDomain($remotehost);
    }
  }
  return $soap_org;
}

# SURFnet function to get the IP ranges from an organisation.
function getorgif($org, $soapurl, $soapuser, $soappass) {
  require_once('include/nusoap.php');
  $soap_client = new soapclient($soapurl, true);
  $soap_client->setCredentials($soapuser, $soappass);
  $soap_err = $soap_client->getError();
  if ($soap_err) {
    echo "SOAPERR: $soap_err<br />\n";
    return "false";
  }
  $soap_klanten = array("var_type" => "klantafkorting", "var_value" => "$org", "version" => "1.0");
  $soap_result = $soap_client->call('getKlantSingle', array('invoer' => $soap_klanten));
  $soap_interfaces = $soap_result["ipv4"];
  $soap_ipv4_ranges = "";
  foreach ($soap_interfaces as $key => $value) {
    $prefix = $value["prefix"];
    $soap_ipv4_ranges .= "$prefix" . ";";
  }
  $soap_ipv4_ranges = trim($soap_ipv4_ranges, ";");
  return "$soap_ipv4_ranges";
}
?>
