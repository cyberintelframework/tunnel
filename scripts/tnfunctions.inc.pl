#!/usr/bin/perl 

######################################
# Function library for tunnel server #
# SURFnet IDS                        #
# Version 1.04.01                    #
# 10-01-2007                         #
# Jan van Lith & Kees Trippelvitz    #
######################################

#####################
# Changelog:
# 1.04.02 Modified info header
# 1.04.01 Initial release
#####################

###############################################
# INDEX
###############################################
# 1             All CHK functions
# 1.01          chkdhclient
# 2		All GET functions
# 2.01		getts
# 2.02		getec
# 2.03		getlocalgw
# 2.04		getnetwork
# 2.05		getifip
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
    if ($err ne "") {
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

return "true";
