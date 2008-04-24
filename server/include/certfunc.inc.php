<?php

####################################
# SURFnet IDS 2.10.00
# Changeset 002
# 01-04-2008
# Jan van Lith & Kees Trippelvitz
####################################

#####################
# Changelog:
# 002 Added mac regexp to extractvars
# 001 Excluded RIPE-CIDR-BLOCK from whois
#####################

function logdb($sensorid, $log, $args) {
  global $pgconn;
  if ($sensorid != "" && $log != "") {
    $date = date("U");

    $pattern = '/^[0-9]*$/';
    if (preg_match($pattern, $sensorid)) {
      $sql_log = "INSERT INTO sensors_log (sensorid, timestamp, logid, args) VALUES ('$sensorid', '$date', '$log', '$args')";
      $result_log = pg_query($pgconn, $sql_log);
    } else {
      $sql_getids = "SELECT id FROM sensors WHERE keyname = '$sensorid'";
      $result_getids = pg_query($sql_getids);
      while ($row = pg_fetch_assoc($result_getids)) {
        $sid = $row['id'];
        $sql_log = "INSERT INTO sensors_log (sensorid, timestamp, logid, args) VALUES ('$sid', '$date', '$log', '$args')";
        $result_log = pg_query($pgconn, $sql_log);
      }
    }
  }
}

function debug_input() {
  global $c_debug_input;
  global $clean;
  global $tainted;
  if ($c_debug_input == 1) {
    echo "<pre>";
    echo "TAINTED:\n";
    print_r($tainted);
    echo "\n";
    echo "CLEAN:\n";
    print_r($clean);
    echo "</pre><br />\n";
  }
}

function extractvars($source, $allowed) {
  if (!is_array($source)) {
    return 1;
  } else {
    global $clean;
    global $tainted;

    # Setting up the regular expression for an IP address
    $ipregexp = '/^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))';
    $ipregexp .= '\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))';
    $ipregexp .= '\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))';
    $ipregexp .= '\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$/';

    foreach ($source as $key => $var) {
      if (!is_array($var)) {
        $var = trim($var);
        if ($var != "") {
          if (in_array($key, $allowed)) {
            $explodedkey = explode("_", $key);
            $temp = array_pop($explodedkey);
            $count = count($explodedkey);
            if ($count != 0) {
              foreach ($explodedkey as $check) {
                if ($check == "int") {
                  $var = intval($var);
                  $clean[$temp] = $var;
                } elseif ($check == "escape") {
                  $var = pg_escape_string($var);
                  $clean[$temp] = $var;
                } elseif ($check == "html") {
                  $var = htmlentities($var);
                  $clean[$temp] = $var;
                } elseif ($check == "strip") {
                  $var = strip_tags($var);
                  $clean[$temp] = $var;
                } elseif ($check == "md5") {
                  $md5pattern = '/^[a-zA-Z0-9]{32}$/';
                  if (!preg_match($md5pattern, $var)) {
                    $tainted[$temp] = $var;
                  } else {
                    $clean[$temp] = $var;
                  }
                } elseif ($check == "bool") {
                  $var = strtolower($var);
	          $pattern = '/^(t|true|f|false)$/';
                  if (!preg_match($pattern, $var)) {
                    $var = "f";
                  } else {
                    if ($var == "true" || $var == "false") {
                      $var = pgboolval($var);
                    }
                  }
                  $clean[$temp] = $var;
                } elseif ($check == "ip") {
                  if (!preg_match($ipregexp, $var)) {
                    $tainted[$temp] = $var;
                  } else {
                    $clean[$temp] = $var;
                  }
                } elseif ($check == "net") {
                  $ar_test = explode("/", $var);
                  $ip_test = $ar_test[0];
                  $mask_test = intval($ar_test[1]);
                  if (preg_match($ipregexp, $ip_test) && $mask_test >= 0 && $mask_test <= 32) {
                    $clean[$temp] = $var;
                  } else {
                    $tainted[$temp] = $var;
                  }
                } elseif ($check == "mac") {
                  $macregexp = '/^([a-zA-Z0-9]{2}:){5}[a-zA-Z0-9]{2}$/';
                  if (preg_match($macregexp, $var)) {
                    $clean[$temp] = $var;
                  } else {
                    $tainted[$temp] = $var;
                  } 
                } elseif (!in_array($temp, $clean)) {
                  $tainted[$temp] = $var;
                }
              }
            } else {
              $tainted[$temp] = $var;
            } // $count != 0
          } // in_array($key, $allowed)
        } // $var != ""
      } else {
        $tainted[$key] = $var;
      } // !is_array($var)
    } // foreach
  } // !is_array($source)
  return 0;
}

function checkident($ident, $type) {
  global $pgconn;
  $type = intval($type);
  $ident = pg_escape_string($ident);
  $sql = "SELECT orgid FROM org_id WHERE identifier = '" .$ident. "' AND type = $type";
  $result = pg_query($pgconn, $sql);
  $num = pg_num_rows($result);
  if ($num == 0) {
    return 0;
  } else {
    $orgid = pg_result($result, 0);
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
    $fp = @fsockopen($server,43,$errno,$errstr,15);
    if (!$fp) {
      next;
    } else {
      fputs($fp,"$remoteip\r\n");
      while(!feof($fp)) {
        $line = fgets($fp,256);
        $pattern = '/^.*netname:.*$/';
        if (preg_match($pattern, $line)) {
          $regel = explode(":", $line);
          $org_ident = trim($regel[1]);
          if ($org_ident != "ERX-NETBLOCK" && $org_ident != "IANA-BLK" && $org_ident != "RIPE-CIDR-BLOCK") {
            $found = 1;
            break;
          } else {
            $org_ident = "";
          }
        }
      }
      fclose($fp);
    }
    if ($found == 1) {
      break;
    }
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
function getorg($ip, $soapurl, $soapuser, $soappass) {
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
