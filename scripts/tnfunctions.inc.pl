#!/usr/bin/perl

####################################
# Function library                 #
# SURFids 3.00                     #
# Changeset 006                    #
# 26-08-2009                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 006 Fixed bug #175
# 005 Fixed bug #153
# 004 Fixed get_man with proper escaping
# 003 Added in_network, updated INDEX
# 002 Added parse_upx, reordered functions
# 001 version 2.10.00 release
#####################

use POSIX;

$f_log_debug = 0;
$f_log_info = 1;
$f_log_warn = 2;
$f_log_error = 3;
$f_log_crit = 4;

###############################################
# INDEX
###############################################
# 1	All CHK functions
# 1.01      chkdhclient
#
# 2	All GET functions
# 2.01		getts
# 2.03		getlocalgw
# 2.04		getnetwork
# 2.05		getifip
# 2.06		getdatetime
# 2.07		getifmask
#
# 3	ALL DB functions
# 3.01		dbremoteip
# 3.02		dbnetconf
# 3.03		dbmacaddr
# 3.04      dbquery
# 3.05      dbnumrows
# 3.06		dbconnect
# 3.07      dbdisconnect
#
# 4 ALL routing functions
# 4.01		addroute
# 4.02		delroute
# 4.03		adddefault
# 4.04      chkroute
# 4.05		flushroutes
#
# 5 ALL rule functions
# 5.01		deliprules
# 5.02		ipruleadd
# 5.03      ipruledel
# 5.04      chkrule
# 5.05      getrulenumber
#
# 6 ALL ARP functions
# 6.01		add_arp_cache
# 6.02		add_arp_alert
# 6.03		add_host_type
# 6.04		add_proto_type
# 6.05		refresh_protos
# 6.06		refresh_static
# 6.07		refresh_cache
# 6.08		get_man
# 6.09		chk_static_arp
# 6.10		chk_dhcp_server
#
# 7 ALL tool functions
# 7.01		hextoip
# 7.02		colonmac
# 7.03		ip2long
# 7.04		long2ip
# 7.05		bc
# 7.06		network
# 7.07		dec2bin
# 7.08		bin2dec
# 7.09		validip
# 7.10		gw
# 7.11      cidr
# 7.12		in_array
# 7.13      escape_dev
# 7.14      in_network
#
# 9 ALL misc functions
# 9.01		killdhclient
# 9.02		printenv
# 9.03		startdhcp
# 9.04		sendmail
# 9.05		logsys
# 9.06		startstatic
# 9.07		check_interface_ip
# 9.08      sys_exec
# 9.10      parse_upx
###############################################

#####################################
# 1 ALL CHK functions
#####################################

# 1.01 chkdhclient
# Function to check if there's a dhclient running for a specific tap device
# Returns 0 if dhclient is running
# Returns 1 if no dhclient was found running
sub chkdhclient() {
  my ($chk, $tap);
  $tap = $_[0];
  $chk = `ps -ef | grep -v grep | grep dhclient3 | grep "^.*$tap\$" | wc -l`;
  if ($chk > 0) {
    return 0;
  } else {
    return 1;
  }
  return 0;
}

#####################################
# 2 ALL GET functions
#####################################

# 2.01 getts
# Function to get the current date in a human readable format
# Returns date as "day-month-year hour:min:sec"
sub getts() {
  my ($ts, $year, $month, $day, $hour, $min, $sec, $timestamp);
  $ts = time();
  $year = localtime->year() + 1900;
  $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  $hour = localtime->hour();
  if ($hour < 10) {
    $hour = "0" . $hour;
  }
  $min = localtime->min();
  if ($min < 10) {
    $min = "0" . $min;
  }
  $sec = localtime->sec();
  if ($sec < 10) {
    $sec = "0" . $sec;
  }

  $timestamp = "$day-$month-$year $hour:$min:$sec";
}

# 2.03 getlocalgw
# Function to get the IP address of the local gateway
# Returns false if no gateway was found
sub getlocalgw() {
  my ($gw);
  $gw = `route -n | grep -i "0.0.0.0" | grep -i UG | awk '{print \$2}'`;
  chomp($gw);
  if ("$gw" eq "") {
    return "false";
  } else {
    return $gw;
  }
}

# 2.04 getnetwork
# Function to retrieve the network when given an IP and netmask
sub getnetwork() {
  my ($ip, $nm, $network);
  $ip = $_[0];
  $nm = $_[1];
  chomp($ip);
  chomp($nm);
  if ($ip && $nm) {
    $network = `$c_surfidsdir/scripts/ipcalc $ip $nm | grep -i network | awk '{print \$2}'`;
    chomp($network);
    return $network;
  } else {
    return "false";
  }
  return "false";
}

# 2.05 getifip
# Function to retrieve the IP address from an interface
# Returns IP address on success
# Returns false on failure
sub getifip() {
  my ($if, $ip);
  $if = $_[0];
  #$ip = `ifconfig $if | grep "inet addr" | awk '{print \$2}' | awk -F: '{print \$2}'`;
  $ip = `ifconfig $if | head -n2 | tail -n1 | grep -v MTU | awk '{print \$2}' | awk -F: '{print \$2}'`;
  chomp($ip);
  if ("$ip" ne "") {
    return $ip;
  } else {
    return "false";
  }
  return "false";
}

# 2.06 getdatetime
# Function to generate a human readable date/time string
# Returns string
sub getdatetime {
  my $stamp = $_[0];
  $tm = localtime($stamp);
  my $ss = $tm->sec;
  my $mm = $tm->min;
  my $hh = $tm->hour;
  my $dd = $tm->mday;
  my $mo = $tm->mon + 1;
  my $yy = $tm->year + 1900;
  if ($ss < 10) { $ss = "0" .$ss; }
  if ($mm < 10) { $mm = "0" .$mm; }
  if ($hh < 10) { $hh = "0" .$hh; }
  if ($dd < 10) { $dd = "0" .$dd; }
  if ($mo < 10) { $mo = "0" .$mo; }
  my $datestring = "$dd-$mo-$yy $hh:$mm:$ss";
  return $datestring;
}

# 2.07 getifmask
# Function to retrieve the subnet mask from an interface
# Returns subnet mask on success
# Returns false on failure
sub getifmask() {
  my ($if, $ip);
  $if = $_[0];
  #$ip = `ifconfig $if | grep "Mask:" | awk -F":" '{print \$4}'`;
  $ip = `ifconfig $if | head -n2 | tail -n1 | grep -v MTU | awk -F":" '{print \$4}'`;
  chomp($ip);
  if ("$ip" ne "") {
    return $ip;
  } else {
    return "false";
  }
  return "false";
}

#####################################
# 3 ALL DB functions
#####################################

# 3.01 dbremoteip
# Function that retrieves the remoteip given a tap device
# Returns remoteip on success
# Returns false on failure
sub dbremoteip() {
  my ($sth, $tap, @row, $remoteip);
  $tap = $_[0];
  chomp($tap);

  $sth = $dbh->prepare("SELECT remoteip FROM sensors WHERE tap = '$tap'");
  $execute_result = $sth->execute();
  @row = $sth->fetchrow_array;
  $remoteip = $row[0];
  if ("$remoteip" eq "") {
    return "false";
  } else {
    return $remoteip;
  }
  return "false";
}

# 3.02 dbnetconf
# Function that retrieves the netconf given a tap device
# Returns netconf on success
# Returns false on failure
sub dbnetconf() {
  my ($sth, $tap, @row, $remoteip, $er);
  $tap = $_[0];
  chomp($tap);

  $sth = $dbh->prepare("SELECT netconf FROM sensors WHERE tap = '$tap'");
  $er = $sth->execute();
  @row = $sth->fetchrow_array;
  $netconf = $row[0];
  if ("$netconf" eq "") {
    return "false";
  } else {
    return $netconf;
  }
  return "false";
}

# 3.03 dbmacaddr
# Function that retrieves the mac address for a specific sensor and remoteip
# Returns mac on success
# Returns false on failure
sub dbmacaddr() {
  my ($sth, $mac, $sensor, $remoteip, @row, $sql, $er, $vlan);
  $sensor = $_[0];
  $vlan = $_[1];

  chomp($sensor);

  $res = &dbquery("SELECT mac FROM sensors WHERE keyname = '$sensor' AND vlanid = $vlan");
  @row = $res->fetchrow_array;
  $mac = $row[0];
  if ("$mac" eq "") {
    return "false";
  } else {
    return $mac;
  }
  return "false";
}

# 3.04 dbquery
# Performs a query to the database. If the query fails, log the query to the database
# and return false. Otherwise, return the data handle.
sub dbquery {
	my $sql = $_[0];
	
	if (!$dbh) {
		&logsys($f_log_error, "DB_ERROR", "No database handler!");
		return 'false';
	}
	$sth = $dbh->prepare($sql);
	$er = $sth->execute();
    $errstr = $sth->errstr;
    chomp($sql);
	if (!$er) {
		&logsys($f_log_error, "DB_QUERY_FAIL", $sql);
        &logsys($f_log_error, "DB_QUERY_FAIL", $errstr);
        return 'false';
	} else {
        if ($c_log_success_query == 1) {
    		&logsys($f_log_debug, "DB_QUERY_OK", $sql);
        }
	}

	return $sth;
}

# 3.05 dbnumrows
# Performs a query to the database and return the amount of rows
sub dbnumrows() {
  my ($sql, $er, $sth);
  $sql = $_[0];

  if (!$dbh) {
    return 0;
  }
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
  if (!$er) {
    return 0;
  }
  return $sth->rows;
}

# 3.06 dbconnect
# Function to connect to the database
# Returns "true" on success
# Returns "false" on failure
sub dbconnect() {
  my ($ts, $pgerr);
  our $dbh = DBI->connect($c_dsn, $c_pgsql_user, $c_pgsql_pass);
  if ($dbh ne "") {
    return "true";
  } else {
    return "false";
  }
}

# 3.07 dbdisconnect
# Closes the DB connection
sub dbdisconnect() {
	if ($sth) {
		$sth->finish;
	}
	if ($dbh) {
		$dbh->disconnect();
	}
}

#####################################
# 4 ALL routing functions
#####################################

# 4.01 addroute
# Function to add a route to a routing table
# Returns 0 on success
# Returns non-zero on failure
sub addroute() {
  my ($network, $tap, $tapip, $table);
  $network = $_[0];
  $tap = $_[1];
  $tapip = $_[2];
  $table = $_[3];
  chomp($network);
  chomp($tap);
  chomp($tapip);
  chomp($table);
  `ip route add $network dev $tap src $tapip table $table`;
  if ($? == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 4.02 delroute
# Function to delete a route from a routing table
# Returns 0 on success
# Returns non-zero on failure
sub delroute() {
  my ($network, $tap, $tapip, $table);
  $network = $_[0];
  $tap = $_[1];
  $tapip = $_[2];
  $table = $_[3];
  chomp($network);
  chomp($tap);
  chomp($tapip);
  chomp($table);
  `ip route del $network dev $tap src $tapip table $table`;
  if ($? == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 4.03 adddefault
# Function to add a default route to a routing table
# Returns 0 on success
# Returns non-zero on failure
sub adddefault() {
  my ($gw, $table);
  $gw = $_[0];
  $table = $_[1];
  chomp($gw);
  chomp($table);
  `ip route add default via $gw table $table`;
  if ($? == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 4.04 chkroute
# Function to check for the existance of a route given an IP address
sub chkroute() {
    my ($remoteip, $chk);
    $remoteip = $_[0];
    chomp($remoteip);
    $chk = `ip route list | grep '\\b$remoteip\\b' | wc -l`;
    if ($chk == 0) {
        return;
    } else {
        return true;
    }
}

# 4.05 flushroutes
# Function to flush the routing table for a specific tap device
# Returns 0 on success
# Returns non-zero on failure
sub flushroutes() {
  my ($tap);
  $tap = $_[0];
  chomp($tap);
  $ec = sys_exec("ip route flush table $tap");
  return $ec;
}

#####################################
# 5 ALL rule functions
#####################################

# 5.01 deliprules
# Function to delete all ip rules for a specific tap device
# Returns 0 on success
# Returns non-zero on failure
sub deliprules() {
  my (@total, $ip, $tap, $ec, $e, $nr);
  $tap = $_[0];
  chomp($tap);

  $e = 0;
  $esctap = &escape_dev($tap);
  @total = `ip rule list | grep '\\b$esctap\\b' | awk '{print \$3}'`;
  foreach $ip (@total) {
    chomp($ip);
    $ec = sys_exec("ip rule del from $ip table $tap");
    if ($ec != 0) { $e = 1; }
  }
  $nr = getrulenumber($esctap);
  @total = `ip rule list | grep '\\b$nr\\b' | awk '{print \$3}'`;
  foreach $ip (@total) {
    chomp($ip);
    $ec = sys_exec("ip rule del from $ip table $tap");
    if ($ec != 0) { $e = 2; }
  }
  return $e;
}

# 5.02 ipruleadd
# Function to add an ip rule for a specific tap device
# Returns "true" on success
# Returns "false" on failure
sub ipruleadd() {
  my ($tap, $tapip);
  $tap = $_[0];
  $tapip = $_[1];
  chomp($tap);
  chomp($tapip);

  `ip rule add from $tapip table $tap`;
  if ($? == 0) {
    return "true";
  } else {
    return "false";
  }
  return "false";
}

# 5.03 ipruledel
# Function to add an ip rule for a specific tap device
# Returns "true" on success
# Returns "false" on failure
sub ipruledel() {
  my ($tap, $tapip);
  $tap = $_[0];
  $tapip = $_[1];
  chomp($tap);
  chomp($tapip);

  `ip rule del from $tapip table $tap`;
  if ($? == 0) {
    return "true";
  } else {
    return "false";
  }
  return "false";
}

# 5.04 chkrule
# Function to check for the existance of a rule given a device
sub chkrule() {
    my ($dev, $nr, $chk, $escdev);
    $dev = $_[0];
    chomp($dev);
    $escdev = &escape_dev($dev);
    $chk = `ip rule list | grep '\\b$escdev\\b' | wc -l`;
    if ($chk == 0) {
        $nr = getrulenumber($escdev);
        $chk = `ip rule list | grep '\\b$nr\\b' | wc -l`;
    }
    chomp($chk);
    return $chk;
}

# 5.05 getrulenumber
# Retrieves the table number for a rule given a tap device
sub getrulenumber() {
    my ($dev, $nr, $escdev);
    $dev = $_[0];
    $escdev = &escape_dev($dev);
    $nr = `grep "\\b$escdev\\b" /etc/iproute2/rt_tables | awk '{print \$1}'`;
    chomp($nr);
    if ("$nr" ne "") {
        return $nr;
    } else {
        return "false";
    }
}

#####################################
# 6 ALL ARP functions
#####################################

# 6.01 add_arp_cache
# Function to add an entry in the scripts ARP cache
# Returns 0 on success
# Returns non-zero on failure
sub add_arp_cache() {
  my ($mac, $ip, $sensorid, $sql, $sth, $er, $cache_ip, $ts, $man);
  $mac = $_[0];
  $ip = $_[1];
  $sensorid = $_[2];
  chomp($mac);
  chomp($ip);
  chomp($sensorid);
  $ts = time();

  if ("$sensorid" eq "") {
    return 1;
  }

  if ("$ip" eq "") {
    return 2;
  }

  if ("$mac" eq "") {
    return 3;
  } elsif ("$mac" eq "00:00:00:00:00:00") {
    return 4;
  } elsif ("$mac" eq "FF:FF:FF:FF:FF:FF") {
    return 4;
  } elsif ("$mac" eq "ff:ff:ff:ff:ff:ff") {
    return 4;
  }

  if (exists $arp_cache{"$mac"}) {
    # MAC address exists in the ARP cache
    $cache_ip = $arp_cache{"$mac"};
    if ("$ip" ne "$cache_ip" && "$ip" ne "0.0.0.0") {
      # MAC address has a new IP address.
      $arp_cache{"$mac"} = $ip;

      if ("$dbconn" ne "false") {
        # Update Tap info to the database for the current $sensor.
        $sql = "UPDATE arp_cache SET ip = '$ip', last_seen = $ts WHERE mac = '$mac' AND sensorid = '$sensorid'";
        $er = $dbh->do($sql);
      }
    }
  } else {
    if ("$dbconn" ne "false") {
      # MAC doesn't exist in local ARP cache
      $sql = "SELECT id FROM arp_cache WHERE sensorid = $sensorid AND ip = '$ip'";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();

      $man = get_man($mac);
      if ("$man" eq "false") {
        $man = "";
      }

      # Check if we can find a cache ID for the sensorid - ip combination
      @row = $sth->fetchrow_array;
      $cacheid = $row[0];
      if ("$cacheid" ne "") {
        # Modifying ARP cache
        $sql = "UPDATE arp_cache SET mac = '$mac', last_seen = $ts, manufacturer = E'$man' WHERE sensorid = $sensorid AND ip = '$ip'";
        $sth = $dbh->prepare($sql);
        $er = $sth->execute();

        for my $cachemac ( keys %arp_cache ) {
          my $cacheip = $arp_cache{$cachemac};
          if ("$cacheip" eq "$ip") {
            delete $arp_cache{"$cachemac"};
            $arp_cache{"$mac"} = $ip;
          }
        }
        return 0;
      }
      # FIXME
      # This might actually be wrong. Do we really want to insert this record if we have possible just updated a similar
      # record?
      # Possible solution: add an "} else {" around this, which will make it "Update if exists, else insert", which 
      # sounds more logical.
      # 
      # Added as bug #151
      $sql = "INSERT INTO arp_cache (mac, ip, sensorid, last_seen, manufacturer) VALUES ('$mac', '$ip', $sensorid, $ts, E'$man')";
      $er = $dbh->do($sql);
    }
    $arp_cache{"$mac"} = $ip;
  }
  return 0;
}

# 6.02 add_arp_alert
# Function to add an ARP alert to the database
# Returns 0 on success
# Returns non-zero on failure
sub add_arp_alert() {
  my ($targetmac, $targetip, $sourcemac, $sourceip, $sensorid, $chk, @row, $sql, $sth, $er, $ts, $expires, $expiry, $mailfile, $subject, $atype, $ident);
  our %dhcp_mail;
  $targetmac = $_[0];
  $sourcemac = $_[1];
  $targetip = $_[2];
  $sourceip = $_[3];
  $sensorid = $_[4];
  $atype = $_[5];
  $ident = $_[6];
  chomp($targetmac);
  chomp($sourcemac);
  chomp($targetip);
  chomp($sourceip);
  chomp($sensorid);
  chomp($atype);
  chomp($ident);
  $ts = time();

  if ("$sensorid" eq "") {
    return 1;
  }

  if ("$atype" eq "") {
    return 6;
  }

  if ($atype == 10) {
    if ("$targetip" eq "") {
      return 2;
    }

    if ("$targetmac" eq "") {
      return 3;
    }
  }

  if ("$sourcemac" eq "") {
    return 4;
  }

  if ("$sourceip" eq "") {
    return 5;
  }

  if (!exists $arp_alert{"$sensorid-$sourcemac-$targetip-$atype"}) {
    $expiry = 0;
  } else {
    $expiry = $arp_alert{"$sensorid-$sourcemac-$targetip-$atype"};
  }
  $cs = time();
  if ($cs > $expiry) {
    if ($atype == 10) {
      $sql = "INSERT INTO attacks (sensorid, timestamp, dst_mac, src_mac, dest, source, severity, atype) ";
      $sql .= " VALUES ($sensorid, $ts, '$targetmac', '$sourcemac', '$targetip', '$sourceip', 1, $atype)";
    } else {
      $sql = "INSERT INTO attacks (sensorid, timestamp, src_mac, source, severity, atype) ";
      $sql .= " VALUES ($sensorid, $ts, '$sourcemac', '$sourceip', 1, $atype)";
    }
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    if ($atype == 11) {
      if ("$ident" ne "") {
        $sql = "SELECT last_value FROM attacks_id_seq";
        $sth = $dbh->prepare($sql);
        $er = $sth->execute();
        @row = $sth->fetchrow_array;
        $aid = $row[0];
        if ("$aid" ne "") {
          $sql = "INSERT INTO details (attackid, sensorid, type, text) ";
          $sql .= " VALUES ($aid, $sensorid, 30, '$ident')";
          $sth = $dbh->prepare($sql);
          $er = $sth->execute();
        }
      }
    }

    # Setting up expiry date
    $expires = $ts + $c_arp_alert_expiry;
    $arp_alert{"$sensorid-$sourcemac-$targetip-$atype"} = $expires;

    $sql_getsid = "SELECT keyname, vlanid FROM sensors WHERE id = '$sensorid'";
    $sth_getsid = $dbh->prepare($sql_getsid);
    $er = $sth_getsid->execute();
    @row_sid = $sth_getsid->fetchrow_array;
    $keyname = $row_sid[0];
    $vlanid = $row_sid[1];
    if ($vlanid != 0) {
      $keyname = "$keyname-$vlanid";
    }

    if ($atype == 10) {
      # ARP MAIL STUFF
      $mailfile = "/tmp/" .$sensorid. ".arp.mail";
      open(MAIL, "> $mailfile");
      print MAIL "ARP Poisoning attack detected on $keyname!\n\n";
      print MAIL "An attacker with MAC address $sourcemac is trying to take over $targetip ($targetmac)!\n";
      close(MAIL);
      $subject = $c_subject_prefix ."ARP Poisoning attempt detected on $keyname!";

      # email address, mailfile, sensorid, subject, gpg
      for my $email (keys %arp_mail) {
        $temp = $arp_mail{"$email"};
        @temp = split(/-/, $temp);
        $gpg = $temp[0];
        $rcid = $temp[1];
        sendmail($email, $mailfile, $sensorid, $subject, $gpg, $rcid);
      }
    } elsif ($atype == 11) {
      # DHCP MAIL STUFF
      $mailfile = "/tmp/" .$sensorid. ".dhcp.mail";
      open(MAIL, "> $mailfile");
      print MAIL "Rogue DHCP server detected on $keyname!\n\n";
      print MAIL "A host with source address $sourcemac ($sourceip) is trying to offer DHCP leases!\n";
      close(MAIL);
      $subject = $c_subject_prefix ."Rogue DHCP server detected on $keyname!";

      # email address, mailfile, sensorid, subject, gpg
      for my $email (keys %dhcp_mail) {
        $temp = $dhcp_mail{"$email"};
        @temp = split(/-/, $temp);
        $gpg = $temp[0];
        $rcid = $temp[1];
        sendmail($email, $mailfile, $sensorid, $subject, $gpg, $rcid);
      }

      # Setting last_sent timestamp
      $ts = time();
      $sql = "UPDATE report_content SET last_sent = '$ts' WHERE template = 7 AND sensor_id = '$sensorid'";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
    }

    # Removing mailfile
    `rm -f $mailfile`;
  }
  return 0;
}

# 6.03 add_host_type
# Function to add a host type to an ARP cache entry
sub add_host_type() {
  my ($ip, $mac, $type, $sql, $sth, $er, @row, $flag, $flags, $flagstring, @flags_ar, %flags_hash);
  $ip = $_[0];
  $sensorid = $_[1];
  $type = $_[2];
  chomp($ip);
  chomp($sensorid);
  chomp($type);

  # Get the old flags first
  $sql = "SELECT flags FROM arp_cache WHERE ip = '$ip' AND sensorid = '$sensorid'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
  @row = $sth->fetchrow_array;
  $flags = $row[0];
  if ("$flags" ne "") {
    @flags_ar = split(/,/, $flags);
    %flags_hash = ();
    foreach $flag (@flags_ar) {
      $flags_hash{"$flag"} = 0;
    }
    if (!exists $flags_hash{"$type"}) {
      if ("$flags" ne "") {
        $flagstring = $flags . ", $type";
      } else {
        $flagstring = "$type";
      }
    } else {
      $flagstring = $flags;
    }
  } else {
    $flagstring = "$type";
  }

  $sql = "UPDATE arp_cache SET flags = '$flagstring' WHERE ip = '$ip' AND sensorid = '$sensorid'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
  return 0;
}

# 6.04 add_proto_type
# Function to add a protocol type to the sensor sniff logs
sub add_proto_type() {
  my ($head, $nr, $proto, $sql, $sth, $er, @row, $id);
  $sensorid = $_[0];
  $head = $_[1];
  $nr = $_[2];
  chomp($sensorid);
  chomp($head);
  chomp($nr);

  if ("$nr" eq "") {
    return 1;
  }

  # Default protocol name is Unknown
  $proto = "Unknown";

  # Getting protocol name if exists
  if ($head == 0) {
    if (exists $ethernettypes{"$nr"}) {
      $proto = $ethernettypes{"$nr"};
    }
    $sniff_protos_eth{$nr} = 0;
  } elsif ($head == 1) {
    if (exists $iptypes{"$nr"}) {
      $proto = $iptypes{"$nr"};
    }
    $sniff_protos_ip{$nr} = 0;
  } elsif ($head == 11) {
    if (exists $icmptypes{"$nr"}) {
      $proto = $icmptypes{"$nr"};
    }
    $sniff_protos_icmp{$nr} = 0;
  } elsif ($head == 12) {
    if (exists $igmptypes{"$nr"}) {
      $proto = $igmptypes{"$nr"};
    }
    $sniff_protos_igmp{$nr} = 0;
  } elsif ($head == 11768) {
    if (exists $dhcptypes{$nr}) {
      $proto = $dhcptypes{$nr};
    }
    $sniff_protos_dhcp{$nr} = 0;
  }
#  print "ADDPROTOTYPE: SID $sensorid - HEAD $head - NR $nr - PROTO $proto\n";

  $sql = "INSERT INTO sniff_protos (sensorid, parent, number, protocol) VALUES ('$sensorid', '$head', '$nr', '$proto')";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
  return 0;
}

# 6.05 refresh_protos
# Function to refresh the known protos hash
sub refresh_protos() {
  my ($head, $nr, @row, $er, $sth, $sql);
  $head = $_[0];
  chomp($head);
  if ($head == 0) {
    # Filling the local scripts protocol list (ETHERNETTYPES)
    $sql = "SELECT number FROM sniff_protos WHERE sensorid = $sensorid AND parent = 0";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    %sniff_protos_eth = ();
    while (@row = $sth->fetchrow_array) {
      $nr = $row[0];
      $sniff_protos_eth{"$nr"} = 0;
    }
  } elsif ($head == 1) {
    # Filling the local scripts protocol list (IPTYPES)
    $sql = "SELECT number FROM sniff_protos WHERE sensorid = $sensorid AND parent = 1";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    %sniff_protos_ip = ();
    while (@row = $sth->fetchrow_array) {
      $nr = $row[0];
      $sniff_protos_ip{"$nr"} = 0;
    }
  } elsif ($head == 11) {
    # Filling the local scripts protocol list (ICMPTYPES)
    $sql = "SELECT number FROM sniff_protos WHERE sensorid = $sensorid AND parent = 11";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    %sniff_protos_icmp = ();
    while (@row = $sth->fetchrow_array) {
      $nr = $row[0];
      $sniff_protos_icmp{"$nr"} = 0;
    }
  } elsif ($head == 12) {
    # Filling the local scripts protocol list (IGMPTYPES)
    $sql = "SELECT number FROM sniff_protos WHERE sensorid = $sensorid AND parent = 12";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    %sniff_protos_igmp = ();
    while (@row = $sth->fetchrow_array) {
      $nr = $row[0];
      $sniff_protos_igmp{"$nr"} = 0;
    }
  } elsif ($head == 11768) {
    # Filling the local scripts protocol list (DHCPTYPES)
    $sql = "SELECT number FROM sniff_protos WHERE sensorid = $sensorid AND parent = 11768";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    %sniff_protos_dhcp = ();
    while (@row = $sth->fetchrow_array) {
      $nr = $row[0];
      $sniff_protos_dhcp{"$nr"} = 0;
    }
  }
  return "true";
}

# 6.06 refresh_static
# Function to refresh the detectarp static list hash
sub refresh_static() {
  my ($sql, $sth, $er, @row, $db_mac, $dp_ip);
  $sql = "SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
  while (@row = $sth->fetchrow_array) {
    $db_mac = $row[0];
    $db_ip = $row[1];
    $arp_static{"$db_ip"} = $db_mac;
  }
  return 0;
}

# 6.07 refresh_cache
# Function to refresh the arp cache of the detect arp script
sub refresh_cache() {
  my ($sql, $sth, $er, @row, $db_mac, $db_ip);
  $sql = "SELECT mac, ip FROM arp_cache WHERE sensorid = $sensorid";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  while (@row = $sth->fetchrow_array) {
    $db_mac = $row[0];
    $db_ip = $row[1];
    $arp_cache{"$db_mac"} = $db_ip;
  } 
  return 0;
}

# 6.08 get_man
# Function to retrieve the manufacturer of a certain network card
# based on the given mac address.
# Returns manufacturer name on success
# Returns false on failure
sub get_man() {
  my ($mac, $prefix, @prefix_ar, $man);
  $mac = $_[0];
  chomp($mac);
  @prefix_ar = split(/:/, $mac);
  $prefix = "$prefix_ar[0]:$prefix_ar[1]:$prefix_ar[2]";
  $man = `grep -i "$prefix" $c_surfidsdir/scripts/oui.txt | awk '{sub(/(..):(..):(..)/,"");sub(/^[ \t]+/, "");print}'`;
  chomp($man);
  $man =~ s/'/\\'/;
  if ("$man" eq "") {
    return "false";
  } else {
    return $man;
  }
}


# 6.09 chk_static_arp
# Function to check an IP/MAC pair versus the static list in the database
# Returns 0 on success
# Returns non-zero on failure
sub chk_static_arp() {
  my ($mac, $ip, $sensorid, $chk, $staticmac, @row, $sql, $sth, $er, $man, $ts);
  $mac = $_[0];
  $ip = $_[1];
  $sensorid = $_[2];
  chomp($mac);
  chomp($ip);
  chomp($sensorid);
  $ts = time();

  if ("$sensorid" eq "") {
    return 1;
  }

  if ("$ip" eq "") {
    return 2;
  }

  if ("$mac" eq "") {
    return 3;
  } elsif ("$mac" eq "00:00:00:00:00:00") {
    return 4;
  } elsif ("$mac" eq "FF:FF:FF:FF:FF:FF") {
    return 4;
  } elsif ("$mac" eq "ff:ff:ff:ff:ff:ff") {
    return 4;
  }

  if (! exists $arp_static{"$ip"}) {
    return 5;
  } else {
    $staticmac = $arp_static{"$ip"};;
    if ("$staticmac" eq "") {
      return 5;
    } else {
      if ("$mac" ne "$staticmac") {
        # Alert!!
        $chk = &add_arp_alert($staticmac, $mac, $ip, $ip, $sensorid, 10);
        # Modifying ARP cache
        $man = &get_man($mac);
        if ("$man" eq "false") {
          $man = "";
        }
        $sql = "UPDATE arp_cache SET mac = '$mac', last_seen = $ts, manufacturer = '$man' WHERE sensorid = $sensorid AND ip = '$ip'";
        $sth = $dbh->prepare($sql);
        $er = $sth->execute();

        delete $arp_cache{"$staticmac"};
        $arp_cache{"mac"} = $ip;
      }
    }
  }
  return 0;
}

# 6.10 chk_dhcp_server
# Function to check if a detected dhcp server is allowed
sub chk_dhcp_server() {
  my ($mac, $ip, $chk, $ident);
  $mac = $_[0];
  $ip = $_[1];
  $ident = $_[2];
  chomp($mac);
  chomp($ip);
  chomp($ident);

  if (! exists $dhcp_static{"$ip"}) {
    $chk = &add_arp_alert("", $mac, "", $ip, $sensorid, 11, "$ident");
  }
  return 0;
}

#####################################
# 7 ALL tool functions
#####################################

# 7.01 hextoip
# Function to convert a hexadecimal IP address to a regular IP address
# Returns IP address
sub hextoip {
  my ($hex) = @_;
  my $P1 = hex(substr($hex,0,2));
  my $P2 = hex(substr($hex,2,2));
  my $P3 = hex(substr($hex,4,2));
  my $P4 = hex(substr($hex,6,2));
  my $quad = "$P1.$P2.$P3.$P4";
  return $quad;
}

# 7.02 colonmac
# Function to convert a string to a regular MAC address
# Returns MAC address
sub colonmac {
  my ($mac) = @_;
  my $P1 = substr($mac,0,2);
  my $P2 = substr($mac,2,2);
  my $P3 = substr($mac,4,2);
  my $P4 = substr($mac,6,2);
  my $P5 = substr($mac,8,2);
  my $P6 = substr($mac,10,2);
  my $colmac = "$P1:$P2:$P3:$P4:$P5:$P6";
  return $colmac;
}

# 7.03 ip2long
# Function to convert an IP address to a long integer
sub ip2long() {
  return unpack("l*", pack("l*", unpack("N*", inet_aton(shift))));
}

# 7.04 long2ip
# Function to convert a long integer to an IP address
sub long2ip() {
  return inet_ntoa(pack("N*", shift));
}

# 7.05 bc
# Function to calculate the broadcast address given an IP address and subnet mask
# Returns broadcast IP address on success
# Returns false on failure
sub bc() {
  my ($address, $mask, $chkip, $bina, $binm, $binn, $cidr, $bcpart, $binbc, $bc);
  $address = $_[0];
  $mask = $_[1];
  chomp($address);
  chomp($mask);
  $chkip = &validip($address);
  if ($chkip != 0) {
    return "false";
  }
  $chkip = &validip($mask);
  if ($chkip != 0) {
    return "false";
  }
  $bina = &dec2bin($address);
  $binm = &dec2bin($mask);
  $cidr = ($binm =~ tr/1//);
  $binn = substr($bina, 0, $cidr);
  $bcpart = 32 - $cidr;
  $binbc = $binn . "1" x $bcpart;
  $bc = &bin2dec($binbc);
  return $bc;
}

# 7.06 network
# Function to calculate the network given an IP address and subnet mask
# Returns network IP address on success
# Returns false on failure
sub network() {
  my ($address, $chkip, $mask, $bina, $binm, $binn, $cidr, $net, $temp);
  $address = $_[0];
  $mask = $_[1];
  chomp($address);
  chomp($mask);
  $chkip = &validip($address);
  if ($chkip != 0) {
    return "false";
  }
  $chkip = &validip($mask);
  if ($chkip != 0) {
    return "false";
  }
  $bina = &dec2bin($address);
  $binm = &dec2bin($mask);
  $cidr = ($binm =~ tr/1//);
  $binn = substr($bina, 0, $cidr);
  $temp = substr($bina, length($binn), (32 - length($binn)));
  $temp =~ s/1/0/g;
  $binn = $binn . $temp;
  $net = &bin2dec($binn);
  return $net;
}

# 7.07 dec2bin
# Function to convert a dotted decimal IP address to a binary string
# Returns binary string on success
# Returns false on failure
sub dec2bin() {
  my ($ip, $chkip, @ip_ar, $bin, $pad, $diff, $i);
  $ip = $_[0];
  chomp($ip);
  $chkip = &validip($ip);
  if ($chkip != 0) {
    return "false";
  }
  $bin = "";
  $pad = "";
  chomp($ip);
  @ip_ar = split(/\./, $ip);

  foreach $dec (@ip_ar) {
    $pad = "";
    $dec = unpack("B32", pack("N", $dec));
    $dec =~ s/^0+(?=\d)//;   # otherwise you'll get leading zeros
    $diff = 8 - length($dec);
    if ($diff > 0) {
      for (1...$diff) {
        $pad .= "0";
      }
    }
    $dec = $pad . $dec;
    $bin .= $dec;
  }
  return $bin;
}

# 7.08 bin2dec
# Function to convert a binary string to a dotted decimal IP address
# Returns IP address on success
sub bin2dec() {
  my ($bin, $dec, $val, $dot, $i, $off);
  $bin = $_[0];
  $dec = "";
  chomp($bin);
  for ($i=0; $i<4; $i++) {
    $off = $i * 8;
    $part = substr($bin, $off, 8);
    $dec .= unpack("N", pack("B32", substr("0" x 32 . $part, -32)));
    if ($i != 3) {
      $dec .= ".";
    }
  }
  return $dec;
}

# 7.09 validip
# Function to check if a given IP address is a valid IP address.
# Returns 0 if the IP is a valid IP number
# Returns 1 if not
sub validip() {
  my ($ip, @ip_ar, $i, $count, $dec);
  $ip = $_[0];
  chomp($ip);
  $regexp = "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))";
  $regexp .= "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))";
  $regexp .= "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))";
  $regexp .= "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\$";
  if ($ip !~ /$regexp/) {
    return 1;
  } else {
    return 0;
  }
  return 1;
}

# 7.10 gw
# Function to calculate the gateway address given an IP address and subnetmask
# Returns gateway IP address on success
# Returns false on failure
sub gw() {
  my ($address, $chkip, $mask, $bina, $binm, $binn, $bing, $cidr, $net);
  $address = $_[0];
  $mask = $_[1];
  chomp($address);
  chomp($mask);
  $chkip = &validip($address);
  if ($chkip != 0) {
    return "false";
  }
  $chkip = &validip($mask);
  if ($chkip != 0) {
    return "false";
  }
  $net = &network($address, $mask);
  @net_ar = split(/\./, $net);
  $old = $net_ar[3];
  $new = $old + 1;
  $gw = $net_ar[0] . "." . $net_ar[1] . "." . $net_ar[2] . "." . $new;
  return $gw;
}

# 7.11 cidr
# # Function to convert a dotted decimal netmask to CIDR notation
# # Returns CIDR notation on success
# # Returns false on failure
sub cidr() {
  my ($mask, $chkip, $cidr, $bina, $binm);
  $mask = $_[0];
  chomp($mask);
  $chkip = &validip($mask);
  if ($chkip != 0) {
    return "false";
  }
  $binm = &dec2bin($mask);
  $cidr = ($binm =~ tr/1//);
  return $cidr;
}

# 7.12 in_array
# Checks to see if a certain value is in the given array
# Usage: in_array(@array, $search_value)
sub in_array() {
  my ($ar, $search) = @_;
  return grep { $search eq $_ } @$ar;
}

# 7.13 escape_dev
# Escapes the device for usage in regular expressions
sub escape_dev() {
    my ($dev, $escdev);
    $dev = $_[0];
    chomp($dev);
    if ($dev !~ /\\\./g) {
        ($escdev = $dev) =~ s/\./\\./;
    } else {
        $escdev = $dev;
    }
    return $escdev;
}

# 7.14 in_network
# Compares 2 IP addresses with submask and checks to 
# see if they are in the same network
sub in_network() {
    my ($ip, $chk, $mask, $cidr, $sub_ip, $sub_chk);
    $ip = $_[0];
    $chk = $_[1];
    $mask = $_[2];
    chomp($ip);
    chomp($chk);
    chomp($mask);

    $cidr = &cidr($mask);
    $b_ip = &dec2bin($ip);
    $b_chk = &dec2bin($chk);

    $sub_ip = substr($b_ip, 0, $cidr);
    $sub_chk = substr($b_chk, 0, $cidr);

    if ($sub_ip eq $sub_chk) {
        return "True";
    } else {
        return "False";
    }
}

#####################################
# 9 ALL misc functions
#####################################

# 9.01 killdhclient
# Function to kill all dhclients for a specific tap device
# Returns 0 on success
# Returns non-zero on failure
sub killdhclient() {
  my ($pid, $tap, $e, $ec, @dhclients);
  $tap = $_[0];
  chomp($tap);

  $e = 0;
  @dhclients = `ps -ef | grep dhclient3 | grep -v grep | grep "^.*$tap\$" | awk '{print \$2}'`;
  foreach $pid (@dhclients) {
    chomp($pid);
    $ec = sys_exec("kill $pid");
    if ($ec != 0) { $e = 1; }
  }
  if (-e "/var/lib/dhcp3/$tap.leases") {
    $ec = sys_exec("rm -f /var/lib/dhcp3/$tap.leases");
    if ($ec != 0) { $e = 2; }
  }
  return $e;
}


# 9.02 printenv
# Function to print all environment variables. Used for debugging purposes.
sub printenv() {
  my ($envlog, $key);
  $envlog = $_[0];

  open(ENVLOG, ">> $envlog");
  print ENVLOG "======================================================\n";
  foreach $key (sort keys(%ENV)) {
    print ENVLOG "$key = $ENV{$key}\n";
  }
  print ENVLOG "======================================================\n";
  close(ENVLOG);
}

# 9.03 startdhcp
# Function to start the dhcp client for a specific tap device
# Returns "true" on success
# Returns "false" on failure
sub startdhcp() {
  my ($tap, $ec);
  $tap = $_[0];
  chomp($tap);

  # The dhclient script (surfids-dhclient) is responsible for setting up
  # the interface and routes when an ip address is obtained. This
  # script is heavily customized for the surfids system, as special
  # routes need to be crafted.
  #
  # See startstatc() below to see the steps that are taken to set
  # up these routes.
  `dhclient3 -lf /var/lib/dhcp3/$tap.leases -cf /etc/surfnetids/dhclient.conf -sf $c_surfidsdir/scripts/surfnetids-dhclient -pf /var/run/dhclient3.$tap.pid $tap`;
#  `/opt/dhcp-3.0.7/bin/dhclient -lf /var/lib/dhcp3/$tap.leases -sf $c_surfidsdir/scripts/surfnetids-dhclient -pf /var/run/dhclient3.$tap.pid $tap`;
  sleep 1;
  if ($? == 0) {
    return "true";
  } else {
    return "false";
  }
  return "false";
}

# 9.04 sendmail()
# Function to send a mail
# Returns 0 on success
# Dies on failure
sub sendmail() {
  my ($email, $mailfile, $sensorid, $subject, $gpg_enabled, $rcid, $sigmailfile, $to_address, $mail_host, $gpg, $msg, $final_mailfile, $chk);
  $email = $_[0];
  $mailfile = $_[1];
  $sensorid = $_[2];
  $subject = $_[3];
  $gpg_enabled = $_[4];
  $rcid = $_[5];
  chomp($email);
  chomp($mailfile);
  chomp($sensorid);
  chomp($subject);
  chomp($gpg_enabled);
  chomp($rcid);
  
  $sigmailfile = "$mailfile" . ".sig";
  $to_address = "$email";
  $mail_host = 'localhost';

  if ($gpg_enabled == 1) {
    # Encrypt the mail with gnupg 
    $gpg = new GnuPG();
    $gpg->clearsign(plaintext => "$mailfile", output => "$sigmailfile", armor => 1, passphrase => $c_passphrase);
  }
  
  #### Create the multipart container
  $msg = MIME::Lite->new (
    From => $c_from_address,
    To => $to_address,
    Subject => $subject,
    Type => 'multipart/mixed'
  ) or die "Error creating multipart container: $!\n";
  
  if ($gpg_enabled == 1) { $final_mailfile  = $sigmailfile; }
  else { $final_mailfile = $mailfile; }

  ### Add the (signed) file
  $msg->attach (
    Type => 'text/plain; charset=ISO-8859-1',
    Path => $final_mailfile,
    Filename => $final_mailfile,
  ) or die "Error adding $final_mailfile: $!\n";
  
  ### Send the Message
  MIME::Lite->send('sendmail');
  $chk = $msg->send;
  
  # Delete the mail and signed mail
  if (-e "$sigmailfile") {
    system("rm $sigmailfile");
  }

  if ("$rcid" ne "") {
    # Setting last_sent timestamp
    $ts = time();
    $sql = "UPDATE report_content SET last_sent = '$ts' WHERE id = '$rcid'";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();
  }

  return 0;
}

# 9.05 logsys
# Function to log messages to the syslog table
sub logsys() {
  my ($ts, $level, $msg, $sql, $er, $tsensor);    # local variables
  our $source;
  our $sensor;
  our $tap;		
  our $pid;
  our $g_vlanid;

  if (!$source) { $source = "unknown"; }
  if (!$sensor) { $sensor = "unknown"; }
  if (!$tap)    { $tap    = "unknown"; }
  if (!$pid)	{ $pid 	  = 0; }
  if (!$g_vlanid) { $g_vlanid = 0; }

  $level = $_[0];	# Loglegel (DEBUG, INFO, WARN, ERROR, CRIT)
  $msg = $_[1];		# Message (START_SCRIPT, STOP_SCRIPT, etc )
  chomp($msg);		

  if ($level >= $c_log_level) {
    if (!$source) { $source = "unknown"; }
    if (!$sensor) { $sensor = "unknown"; }
    if (!$tap)    { $tap    = "unknown"; }
    if (!$pid)  { $pid    = 0; }
    if (!$g_vlanid) { $g_vlanid = 0; }

    if ($_[2]) {
      $args = $_[2];
      chomp($args);
    } else {
      $args = "";
    }

#    $ts = time();
    if ($c_log_method == 2 || $c_log_method == 3) {
      # We need to cleanup the $args and escape all ' and " characters
#      $args =~ s/\'/\\\'/g;
#      $args =~ s/\"/\\\"/g;
      $args =~ s/\'/\'\'/g;
#      $args =~ s/\"/\"\"/g;

      $sql = "INSERT INTO syslog (source, error, args, level, keyname, device, pid, vlanid) VALUES ";
      $sql .= " ('$source', '$msg', '$args', $level, '$sensor', '$tap', $pid, $g_vlanid)";
      if ($dbh) {
       $er = $dbh->do($sql);
      }
    }
    if ($c_log_method == 1 || $c_log_method == 3) {
      $tsensor = $sensor;
      if ($g_vlanid != 0) {
        $tsensor = "$sensor-$g_vlanid";
      }
      $ts = &getts();
      open LOG,  ">>/var/log/surfids.log" || die ("cant open log: $!");
      print LOG "[$ts] $pid $source $tsensor $msg $args\n";
      close LOG;
    }
  }
  return "true";
}

# 9.06 startstatic
# Function to start static networking. Works like 
# startdhcp (4.07) but takes more arguments
sub startstatic() {
    my ($tap, $if_ip, $if_nm, $if_gw, $if_bc);
    $tap = $_[0];
    $if_ip = $_[1];
    $if_nm = $_[2];
    $if_bc = $_[3];
    $if_gw = $_[4];

    # Configure the interface
    `ifconfig $tap $if_ip netmask $if_nm broadcast $if_bc`;

    # Check for existing rules.
    $rulecheck = `ip rule list | grep '\\b$tap\\b' | wc -l`;
    chomp($rulecheck);
    if ($rulecheck == 0) {
        $result = &ipruleadd($tap, $if_ip);
    } else {
        $result = &deliprules($tap);
        $result = &ipruleadd($tap, $if_ip);
        #$checktap = `$c_surfidsdir/scripts/checktap.pl $tap`;
    }

    # Just to be sure, flush the routing table of the tap device.
    &flushroutes($tap);

    # Calculate the network based on the if_ip and the netmask.
    $network = &getnetwork($if_ip, $if_nm);

    # Check if there are any routes present in the main routing table.
    $esctap = &escape_dev($tap);
    $routecheck = `ip route list | grep '\\b$esctap\\b' | wc -l`;
    chomp($routecheck);

    # If none were present, add it. This needs to be done otherwise
    # you'll get an error when adding the default gateway
    # for the tap device routing table.
    if ($routecheck == 0) {
        $result = &addroute($network, $tap, $if_ip, "main");
    }

    # Add default gateway to the routing table of the tap device.
    $result = &adddefault($if_gw, $tap);

    # At this point we can delete the route to the network from the
    # main table as there is now a default gateway in the routing table
    # from the tap device.
    $result = &delroute($network, $tap, $if_ip, "main");

    # Add the route to the network to the routing table of the tap device.
    $result = &addroute($network, $tap, $if_ip, $tap);
}

# 9.07 check_interface_ip
# Function to check if the interface has an IP address. Wait 'timeout'
# seconds to allow (slow) DHCP interfaces to obtain an address
sub check_interface_ip() {
    my ($tap, $timeout, $count, $i);
    $tap = $_[0];
    $timeout = $_[1];

    $ok = 0; $i = 0;
    while ($ok != 1 && $i < $timeout) {
        $tapcheck = `ifconfig $tap`;
        if ($? != 0) {
            $count = 1;
            return -1;
        } else {
            $ok = `ifconfig $tap | head -n2 | tail -n1 | grep -v MTU | wc -l`;
            chomp($ok);
        }
        $i++;
        if ($i == $timeout) {
           return -1;
        }
        sleep 1;
    }
    return 0;
}

# 9.08 sys_exec 
# Executes the specified command. Logs nonzero return value to database.
sub sys_exec {
	my $cmd = $_[0];

	`$cmd`;

	if ($?) {
		&logsys($f_log_debug, "SYS_EXEC_FAIL", "'$cmd' returned $? ($!)");
	} else {
		&logsys($f_log_debug, "SYS_EXEC_OK", $cmd);
	}

	return $?;
}

# 9.10 parse_upx
# Parses the output of a UPX scan
sub parse_upx() {
    my ($input, @res, $status, $info);
    $result = $_[0];
    @res = split(/ /, $result);
    $status = $res[2];
    chomp($status);
    if ($status ne "[OK]") {
        shift(@res);
        shift(@res);
        shift(@res);
        $info = join(" ", @res);
        chomp($info);
        $info =~ s/\; take care!//;
    } else {
        $info = "UPX packed";
    }
    return $info;
}

return "true";
