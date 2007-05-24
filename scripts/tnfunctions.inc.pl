#!/usr/bin/perl 

######################################
# Function library for tunnel server #
# SURFnet IDS                        #
# Version 1.04.05                    #
# 24-05-2007                         #
# Jan van Lith & Kees Trippelvitz    #
######################################

#####################
# Changelog:
# 1.04.05 Added get_man
# 1.04.04 Added getifmask, hextoip, colonmac
# 1.04.03 Added getdatetime
# 1.04.02 Modified info header
# 1.04.01 Initial release
#####################

use POSIX;

###############################################
# INDEX
###############################################
# 1             All CHK functions
# 1.01          chkdhclient
# 1.02		chk_static_arp
# 2		All GET functions
# 2.01		getts
# 2.02		getec
# 2.03		getlocalgw
# 2.04		getnetwork
# 2.05		getifip
# 2.06		getdatetime
# 2.07		getifmask
# 3		ALL DB functions
# 3.01		dbremoteip
# 3.02		dbnetconf
# 3.03		dbmacaddr
# 4		ALL misc functions
# 4.01		printlog
# 4.02		killdhclient
# 4.03		deliprules
# 4.04		flushroutes
# 4.05		printenv
# 4.06		connectdb
# 4.07		startdhcp
# 4.08		ipruleadd
# 4.09		addroute
# 4.10		delroute
# 4.11		adddefault
# 4.12		add_arp_cache
# 4.13		hextoip
# 4.14		colonmac
# 4.15		add_arp_alert
# 4.16		ip2long
# 4.17		long2ip
# 4.18		bc
# 4.19		network
# 4.20		dec2bin
# 4.21		bin2dec
# 4.22		validip
# 4.23		get_man
###############################################

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

# 1.02 chk_static_arp
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

#  $sql = "SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid AND ip = '$ip'";
#  $sth = $dbh->prepare($sql);
#  $er = $sth->execute();

#  # Get the tap ip address of tap device ($tap) from the query result.
#  @row = $sth->fetchrow_array;
  if (! exists $arp_static{"$ip"}) {
    return 5;
  } else {
    $staticmac = $arp_static{"$ip"};;
    if ("$staticmac" eq "") {
      return 5;
    } else {
      if ("$mac" ne "$staticmac") {
        # Alert!!
        $chk = &add_arp_alert($staticmac, $mac, $ip, $sensorid);
        # Modifying ARP cache
        $man = get_man($mac);
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

# 2.02 getec
# Function to get the error code of the last run command
# and translate it into something readable
sub getec() {
  my ($ec);
  if ($? == 0) {
    $ec = "Ok";
  } else {
    $ec = "Err - $?";
  }
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
  $ip = `ifconfig $if | grep "inet addr" | awk '{print \$2}' | awk -F: '{print \$2}'`;
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
  $ip = `ifconfig $if | grep "Mask:" | awk -F":" '{print \$4}'`;
  chomp($ip);
  if ("$ip" ne "") {
    return $ip;
  } else {
    return "false";
  }
  return "false";
}

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
  my ($sth, $mac, $sensor, $remoteip, @row, $sql, $er);
  $sensor = $_[0];
  $remoteip = $_[1];
  chomp($sensor);
  chomp($remoteip);

  $sql = "SELECT mac FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
  $sth = $dbh->prepare($sql);
  &printlog("Prepared query: $sql");
  $er = $sth->execute();
  &printlog("Executed query", "$er");
  @row = $sth->fetchrow_array;
  $mac = $row[0];
  if ("$mac" eq "") {
    return "false";
  } else {
    return $mac;
  }
  return "false";
}

# 4.01 printlog
# Function to print something to a logfile
# Returns 0 on success
# Returns 1 on failure
sub printlog() {
  my ($err, $ts, $msg, $logstring);
  $msg = $_[0];
  $err = $_[1];
  $ts = getts();
  $logstring = "[$ts";
  if ($tap) {
    if ($tap ne "") {
      $logstring .= " - $tap";
    }
  }
  if ($err) {
    if ("$err" ne "") {
      $logstring .= " - $err";
    }
  }
  $logstring .= "] $msg\n";
  if ($logfile) {
    open(LOG, ">> $logfile");
    print LOG $logstring;
    close(LOG);
  }
}

# 4.02 killdhclient
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
    `kill $pid`;
    if ($? != 0) { $e = 1; }
    $ec = getec();
    &printlog("Killing dhclient3 $pid", "$ec");
  }
  if (-e "/var/lib/dhcp3/$tap.leases") {
    `rm -f /var/lib/dhcp3/$tap.leases`;
    if ($? != 0) { $e = 1; }
    $ec = getec();
    &printlog(" Deleted dhcp lease file /var/lib/dhcp3/$tap.leases", "$ec");
  }
  return $e;
}

# 4.03 deliprules
# Function to delete all ip rules for a specific tap device
# Returns 0 on success
# Returns non-zero on failure
sub deliprules() {
  my (@total, $ip, $tap, $ec, $e);
  $tap = $_[0];
  chomp($tap);

  $e = 0;
  @total = `ip rule list | grep -i "$tap" | awk '{print \$3}'`;
  foreach $ip (@total) {
    chomp($ip);
    `ip rule del from $ip table $tap`;
    if ($? != 0) { $e = 1; }
    $ec = getec();
    &printlog("Deleted ip rule: ip rule del from $ip table $tap", $ec);
  }
  return $e;
}

# 4.04 flushroutes
# Function to flush the routing table for a specific tap device
# Returns 0 on success
# Returns non-zero on failure
sub flushroutes() {
  my ($tap);
  $tap = $_[0];
  `ip route flush table $tap`;
  return $?;
}

# 4.05 printenv
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

# 4.06 connectdb
# Function to connect to the database
# Returns "true" on success
# Returns "false" on failure
sub connectdb() {
  my ($ts, $pgerr);
  $dbh = DBI->connect($c_dsn, $c_pgsql_user, $c_pgsql_pass);
  &printlog("Connecting to $c_pgsql_dbname with DSN: $c_dsn");
  if ($dbh ne "") {
    &printlog("Connect result: Ok");
    return "true";
  } else {
    &printlog("Connect result: failed");
    $pgerr = $DBI::errstr;
    chomp($pgerr);
    &printlog("Error message: $pgerr");
    return "false";
  }
}

# 4.07 startdhcp
# Function to start the dhcp client for a specific tap device
# Returns "true" on success
# Returns "false" on failure
sub startdhcp() {
  my ($tap, $ec);
  $tap = $_[0];
  chomp($tap);

  `dhclient3 -lf /var/lib/dhcp3/$tap.leases -sf $c_surfidsdir/scripts/surfnetids-dhclient -pf /var/run/dhclient3.$tap.pid $tap`;
  $ec = getec();
  &printlog("Starting dhclient3 for $tap!", "$ec");
  sleep 1;
  if ($? == 0) {
    return "true";
  } else {
    return "false";
  }
  return "false";
}

# 4.08 ipruleadd
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
  $ec = getec();
  &printlog("ip rule add from $tapip table $tap!", "$ec");
  if ($? == 0) {
    return "true";
  } else {
    return "false";
  }
  return "false";
}

# 4.08 ipruledel
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
  $ec = getec();
  &printlog("ip rule del from $tapip table $tap!", "$ec");
  if ($? == 0) {
    return "true";
  } else {
    return "false";
  }
  return "false";
}

# 4.09 addroute
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

# 4.10 delroute
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

# 4.11 adddefault
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

# 4.12 add_arp_cache
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
    if ("$ip" ne "$cache_ip") {
      # MAC address has a new IP address.
      $arp_cache{"$mac"} = $ip;

      if ("$dbconn" ne "false") {
        # Update Tap info to the database for the current $sensor.
        $sql = "UPDATE arp_cache SET ip = '$ip', sensorid = $sensorid, last_seen = $ts WHERE mac = '$mac'";
        $er = $dbh->do($sql);
      }
    }
  } else {
    if ("$dbconn" ne "false") {
      # Update Tap info to the database for the current $sensor.
      $sql = "SELECT id FROM arp_cache WHERE sensorid = $sensorid AND ip = '$ip'";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();

      $man = get_man($mac);
      if ("$man" eq "false") {
        $man = "";
      }

      # Get the tap ip address of tap device ($tap) from the query result.
      @row = $sth->fetchrow_array;
      $cacheid = $row[0];
      if ("$cacheid" ne "") {
        # Modifying ARP cache
        $sql = "UPDATE arp_cache SET mac = '$mac', last_seen = $ts, manufacturer = '$man' WHERE sensorid = $sensorid AND ip = '$ip'";
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
      $sql = "INSERT INTO arp_cache (mac, ip, sensorid, last_seen, manufacturer) VALUES ('$mac', '$ip', $sensorid, $ts, '$man')";
      $er = $dbh->do($sql);
    }
    $arp_cache{"$mac"} = $ip;
  }
  return 0;
}

# 4.13 hextoip
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

# 4.14 colonmac
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

# 4.15 add_arp_alert
# Function to add an ARP alert to the database
# Returns 0 on success
# Returns non-zero on failure
sub add_arp_alert() {
  my ($targetmac, $targetip, $sourcemac, $sensorid, $chk, @row, $sql, $sth, $er, $ts, $expires, $expiry);
  $targetmac = $_[0];
  $sourcemac = $_[1];
  $targetip = $_[2];
  $sensorid = $_[3];
  chomp($targetmac);
  chomp($targetip);
  chomp($sourcemac);
  chomp($sensorid);
  $ts = time();

  if ("$sensorid" eq "") {
    return 1;
  }

  if ("$targetip" eq "") {
    return 2;
  }

  if ("$targetmac" eq "") {
    return 3;
  }

  if ("$sourcemac" eq "") {
    return 4;
  }

  if (!exists $arp_alert{"$sensorid-$sourcemac-$targetip"}) {
    $sql = "INSERT INTO arp_alert (sensorid, timestamp, targetmac, sourcemac, targetip, type) VALUES ($sensorid, $ts, '$targetmac', '$sourcemac', '$targetip', 1)";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();
    $expires = $ts + $c_arp_alert_expiry;
    $arp_alert{"$sensorid-$sourcemac-$targetip"} = $expires;
  } else {
    $expiry = $arp_alert{"$sensorid-$sourcemac-$targetip"};
    $cs = time();
    if ($cs > $expiry) {
      $sql = "INSERT INTO arp_alert (sensorid, timestamp, targetmac, sourcemac, targetip, type) VALUES ($sensorid, $ts, '$targetmac', '$sourcemac', '$targetip', 1)";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
      $expires = $ts + $c_arp_alert_expiry;
      $arp_alert{"$sensorid-$sourcemac-$targetip"} = $expires;
    }
  }
  return 0;
}

# 4.16 ip2long
# Function to convert an IP address to a long integer
sub ip2long() {
  return unpack("l*", pack("l*", unpack("N*", inet_aton(shift))));
}

# 4.17 long2ip
# Function to convert a long integer to an IP address
sub long2ip() {
  return inet_ntoa(pack("N*", shift));
}

# 4.18 bc
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

# 4.19 network
# Function to calculate the network given an IP address and subnet mask
# Returns network IP address on success
# Returns false on failure
sub network() {
  my ($address, $chkip, $mask, $bina, $binm, $binn, $cidr, $net);
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
  $net = &bin2dec($binn);
  return $net;
}

# 4.20 dec2bin
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

# 4.21 bin2dec
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

# 4.22 validip
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

# 4.23 get_man()
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
  print "PREFIX: $prefix\n";
  $man = `grep -i "$prefix" $c_surfidsdir/scripts/oui.txt | awk '{sub(/(..):(..):(..)/,"");sub(/^[ \t]+/, "");print}'`;
  chomp($man);
  if ("$man" eq "") {
    return "false";
  } else {
    return $man;
  }
}

return "true";
