<?php
####################################
# SURFnet IDS                      #
# Version 1.02.02                  #
# 26-07-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#############################################
# Changelog:
# 1.02.02 Added the stripinput function
# 1.02.01 Initial release
#############################################

# Removes certain strings from the input. This is used to prevent XSS attacks.
function stripinput($input) {
  $pattern_ar = array("<script>", "</script>", "<", "</", ">", "%");
  foreach($pattern_ar as $pattern) {
    $input = str_replace($pattern, '', $input);
  }
  return $input;
}

# Returns the domain portion of a FQDN.
function getDomain($host) {
  $count=0;
  $domain_ar = split("\.", $host);
  $count = count($domain_ar);
  $last = $count - 1;
  if ($domain_ar[$last] == "uk") {
    $tld = $last;
    $uk = $last - 1;
    $domain = $last - 2;
    $domain = $domain_ar[$domain] . "." . $domain_ar[$uk] . "." . $domain_ar[$tld];
  }
  else {
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
    $remotehost = $_SERVER['REMOTE_HOST'];
    $soap_org = getDomain($remotehost);
  }
  else {
    $remoteip = $ip;
    $soap_klanten = array("var_type" => "ip", "var_value" => "$remoteip", "version" => "1.0");
    $soap_result = $soap_client->call('getKlantSingle', array('invoer' => $soap_klanten));
#      foreach ($soap_result as $key => $value) {
#        echo "$key: $value\n";
#      }
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
