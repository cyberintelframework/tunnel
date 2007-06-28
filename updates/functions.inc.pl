#!/usr/bin/perl

#########################################
# Function library for the sensor scripts
# SURFnet IDS
# Version 1.04.28
# 31-05-2007
# Jan van Lith & Kees Trippelvitz
#########################################

################
# Changelog:
# 1.04.29 Added mii-tool check for active interface
# 1.04.28 Fixed a bug with network calculation
# 1.04.27 Fixed client.conf updating bug
# 1.04.26 Added extra ping within chkreach 
# 1.04.25 Removed chkgateway (use chkreach)
# 1.04.24 ifconfig -a switch added
# 1.04.23 Added server subdir to chkwgetauth function
# 1.04.22 Fixed a bug with firewire interfaces and getif()
# 1.04.21 Fixed getsensor bug with .key files
# 1.04.20 Added chkupscript
# 1.04.19 Added networkconf variable
# 1.04.18 Fixed upplstatus
# 1.04.17 Fixed typo
# 1.04.16 Fixed a bug with chkssh
# 1.04.15 Fixed a bug with dhclient3 pid files
# 1.04.14 Added ris support
# 1.04.13 Added startdhcp function
# 1.04.12 Changed path to status.php in chkwgetauth
# 1.04.11 Changed chkwgetauth to check for status.php instead of server_version.txt
# 1.04.10 Removed chkpump and added chkdhclient 
# 1.04.09 Fixed a bug in getnetinfo with nameserver check
# 1.04.08 Added dec2bin, bin2dec, bc, network, cidr
# 1.04.07 Added chkgateway
# 1.04.06 Fixed a bug in fixclientconf
# 1.04.05 Changed chkreach
# 1.04.04 Added chknetworkconf
# 1.04.03 Added chkidsmenu, chkpump, printdelay, printresult
# 1.04.02 Added regexp for validip
# 1.04.01 Initial release
################

use POSIX;

$| = 1;

###############################################
# INDEX
###############################################
# 1 		All CHK functions
# 1.01		chkif
# 1.02		chkopenvpn
# 1.03		chksensorstatus
# 1.04		chkrw
# 1.05		chkca
# 1.06		chkdisabled
# 1.07		chkwgetauth
# 1.08		chktime
# 1.09		chksensorcert
# 1.10		chksensorkey
# 1.11		chkssh
# 1.12		chkclientconf
# 1.13		chkreach
# 1.14		chkidsmenu
# 1.15		chkdhclient
# 1.16		chkdefault
# 1.17		chknetworkconf
# 1.19		chkupscript
# 2		All GET functions
# 2.01		getnetinfo
# 2.02		getnetconf
# 2.03		getsensor
# 2.04		getif
# 2.05		getifip
# 2.06		getportstatus
# 2.07		getresolv
# 2.08		getcerts
# 3		MISC functions
# 3.01		prompt
# 3.02		printmsg
# 3.03		dossh
# 3.04		validip
# 3.05		fixclientconf
# 3.06		updatefile
# 3.07    	setiptables
# 3.08    	setbridge
# 3.09		validvlanid
# 3.10		validvlancount
# 3.11		sleeptimer
# 3.12		printdelay
# 3.13		printresult
# 3.14		clientconftemp
# 3.15		dec2bin
# 3.16		bin2dec
# 3.17		bc
# 3.18		network
# 3.19		cidr
# 3.20		gw
# 3.21		upplstatus
# 3.22		startdhcp
###############################################

#########################
# 1 All CHK functions
#########################

# 1.01 chkif
# Function to check if there is a bridge interface
# Returns 0 if the interface is present
# Returns 1 if not
sub chkif() {
  my ($if, $checkif);
  $if = $_[0];
  chomp($if);
  $checkif = `ip link show | grep $if | wc -l`;
  if ($checkif == 0) {
    return 1;
  } else {
    return 0;
  }
  return 1;
}

# 1.02 chkopenvpn
# Function to check if openvpn is running
# Returns 1 if OpenVPN is not running
# Returns 0 if OpenVPN is running
sub chkopenvpn() {
  my $checkopenvpn = `ps -ef | grep -i openvpn | grep -v grep | wc -l`;
  if ($checkopenvpn == 0) {
    return 1;
  } else {
    return 0;
  }
  return 1;
}

# 1.03 chksensorstatus
# Checking the status of the sensor.
# Returns 0 if both the bridge and openvpn are running
# Returns 1 if the sensor has not been started yet
# Returns 2 if the sensor was disabled by admin
sub chksensorstatus() {
  my $if = $_[0];
  my $checkif = &chkif($if);
  my $checkopenvpn = chkopenvpn();
  my $chkdisabled = chkdisabled();
  if ($chkdisabled == 0) {
    if ($checkif == 0 && $checkopenvpn == 0) {
      return 0;
    } else {
      return 1;
    }
  } else {
    return 2;
  }
  return 1;
}

# 1.04 chkrw
# Function to check the read/write status of the USB stick
# Returns 1 if the sensor is read-only.
# Returns 0 if the sensor is read/write.
sub chkrw() {
  my $touchfile = `mktemp -p $basedir`;
  if ($? != 0) {
    $rmtouch = `rm $touchfile`;
    return 1;
  } else {
    $rmtouch = `rm $touchfile`;
    return 0;
  }
  return 1;
}

# 1.05 chkca
# Function to check the presence of a root certificate (ca.crt)
# Returns 0 if ca.crt is present.
# Returns 1 if ca.crt is not found.
sub chkca() {
  my $file;
  opendir(BDIR, $basedir);
  while($file = readdir(BDIR)) {
    if (! -d $file) {
      if ($file =~ /^ca\.crt$/) {
        return 0;
      }
    }
  }
  return 1;
}

# 1.06 chkdisabled
# Function to check if the sensor was disabled by admin
# Returns 0 if the sensor is not disabled.
# Returns 1 if the sensor is disabled.
sub chkdisabled() {
  my ($sensor, $disabled);
  $sensor = getsensor();
  $disabled = `grep "DISABLED" $basedir/$sensor.crt | wc -l`;
  if ($disabled == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 1.07 chkwgetauth
# Function to check if wget can authenticate himself correctly
# Dependencies: wget
# Returns 0 if authentication succeeded.
# Returns 1 if authentication failed.
sub chkwgetauth() {
  my $wgetarg = $_[0];
  `wget -q $wgetarg --spider $http://$server:$port/server/status.php`;
  if ($? == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 1.08 chktime
# Function to sync the time of the sensor machine with a ntp server
# Dependencies: ntpdate
# Returns 0 if time syncing succeeded.
# Returns 1 if time syncing failed.
sub chktime() {
  `ntpdate -u -b $ntpserver 2>/dev/null`;
  if ($? == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 1.09 chksensorcert
# Function to check the sensor certificate file
# Returns 0 if the sensor certificate passed all checks.
# Returns 1 if the sensor certificate failed the start check.
# Returns 1 if the sensor certificate failed the end check.
sub chksensorcert() {
  my ($i, $line);
  $i = 0;
  open(CERT, "$basedir/$sensor.crt");
  while (<CERT>) {
    $line = $_;
    if ($i == 0) {
      if ($line !~ /^Certificate:$/) {
        close(CERT);
        return 1;
      }
      $i++;
    }
  }
  if ($line !~ /^-----END CERTIFICATE-----$/) {
    close(CERT);
    return 1;
  } else {
    close(CERT);
    return 0;
  }
  close(CERT);
  return 1;
}

# 1.10 chksensorkey
# Function to check the sensor key file
# Returns 0 if the sensor key passed all checks.
# Returns 1 if the sensor key failed the start check.
# Returns 1 if the sensor key failed the end check.
sub chksensorkey() {
  my ($i, $line);
  $i = 0;
  open(KEY, "$basedir/$sensor.key");
  while (<KEY>) {
    $line = $_;
    if ($i == 0) {
      if ($line !~ /^-----BEGIN [A-Z ]* PRIVATE KEY-----$/) {
        close(KEY);
        return 1;
      }
      $i++;
    }
  }
  if ($line !~ /^-----END [A-Z ]* PRIVATE KEY-----$/) {
    close(KEY);
    return 1;
  } else {
    close(KEY);
    return 0;
  }
  close(KEY);
  return 1;
}

# 1.11 chkssh
# Function to check if the SSH daemon is running or not
# Returns 0 if no SSH daemon was found running.
# Returns 1 if an SSH daemon was found running.
sub chkssh() {
  my $checkssh;
  $checkssh = `ps -ef | grep -i sshd | grep -v grep | wc -l`;
  if ($checkssh == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 1.12 chkclientconf
# Function to check the validity of the client.conf file
# Returns 0 if it passed all checks
# Returns 1 if it failed the ca.crt check
# Returns 2 if it failed the sensor.crt check
# Returns 3 if it failed the sensor.key check
# Returns 4 if it failed the server check
# Returns 5 for unknown error
sub chkclientconf() {
  my ($ca, $cert, $key, $line, $server, $sensor);
  $ca = 1;
  $key = 1;
  $cert = 1;
  $server = 1;
  $sensor = getsensor();
  if ($sensor eq "false") {
    return 1;
  }
  open(CLIENT, "$basedir/client.conf");
  while(<CLIENT>) {
    $line = $_;
    if ($line =~ /^remote.*$/) {
      $server = 0;
    }
    if ($line =~ /^ca.*crt$/) {
      $ca = 0;
    }
    if ($line =~ /^key.*$sensor\.key$/) {
      $key = 0;
    }
    if ($line =~ /^cert.*$sensor\.crt$/) {
      $cert = 0;
    }
  }
  close(CLIENT);
  if ($ca == 0 && $key == 0 && $cert == 0 && $server == 0) {
    return 0;
  } elsif ($ca != 0) {
    return 1;
  } elsif ($cert != 0) {
    return 2;
  } elsif ($key != 0) {
    return 3;
  } elsif ($server != 0) {
    return 4;
  } else {
    return 5;
  }
  return 4;
}

# 1.13 chkreach
# Function to check the reachability of an IP address
# Dependencies: ping
# Returns 0 if the IP address was reachable
# Returns 1 if the IP address was not reachable
# Returns 2 if the IP address was invalid
sub chkreach() {
  my ($ip, $pingresult, $chkip);
  $ip = $_[0];
  chomp($ip);
  $chkip = validip($ip);
  if ($chkip == 0) {
    `ping -c 5 -q $ip 2>/dev/null`;
    `ping -c 1 -q $ip 2>/dev/null`;
    return $?;
  } else {
    return 2;
  }
}

# 1.14 chkidsmenu
# Function to check if idsmenu is running
# Returns 0 if idsmenu is running
# Returns 1 if idsmenu is not running
sub chkidsmenu() {
  my ($chk);
  $chk = `ps -ef | grep idsmenu | grep -v grep | wc -l`;
  chomp($chk);
  if ($chk != 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 1.15 chkdhclient
# Function to check if dhclient3 is running for a certain interface
# Returns 0 if dhclient3 is running
# Returns 1 if dhclient3 is not running
sub chkdhclient() {
  my ($chk, $if);
  if ($_[0]) {
    $if = $_[0];
    $chk = `ps -ef | grep dhclient3 | grep $if | grep -v grep | wc -l`;
  } else {
    $chk = `ps -ef | grep dhclient3 | grep -v grep | wc -l`;
  }
  chomp($chk);
  if ($chk == 0) {
    return 1;
  } else {
    return 0;
  }
  return 1;
}

# 1.16 chkdefault
# Function to check for the existance of a default route given an interface
# Returns 0 if a default route is present
# Returns 1 if not
sub chkdefault() {
  my ($chk, $if);
  $if = $_[0];
  chomp($if);
  if (!$if) {
    return 1;
  }
  $chk = `route -n | grep UG | grep 0.0.0.0 | grep $if | wc -l`;
  chomp($chk);
  if ($chk == 0) {
    return 1;
  } else {
    return 0;
  }
  return 1;
}

# 1.17 chknetworkconf
# Function to check the network configuration file
# Returns true if perl syntax was correct
# Returns false if perl syntax was not correct
sub chknetworkconf() {
  my ($chk);
  if (-e "$networkconf") {
    $chk = `wc -l $networkconf`;
    chomp($chk);
    if ($chk == 0) {
      return "false";
    }
    `perl $networkconf 2>/dev/null`;
    $chk = $?;
    if ($chk == 0) {
      return "true";
    } else {
      return "false";
    }
  } else {
    return "false";
  }
  return "false";
}

# 1.19 chkupscript
# Function to check if an up script is running given a default gateway
# Returns 0 if no up script is running
# Returns 1 if an up script is running
sub chkupscript() {
  my ($chk, $gw);
  $gw = $_[0];
  chomp($gw);
  $chk = `ps -ef | grep -v grep | grep perl | grep up | grep $gw | wc -l`;
  chomp($chk);
  if ($chk > 0) {
    $chk = 1;
  }
  return $chk;
}

#########################
# 2 All GET functions
#########################

# 2.01 getnetinfo
# Parsing the network config file to get the info
# Attr: inet, nm, gw, bc, ns
# Returns attribute on success
# Returns 1 when given attribute is unknown
# Returns 2 if the given interface was not found
sub getnetinfo() {
  my ($method, $attr, $if, $domain, $name, $i);
  $attr = $_[0];
  $if = $_[1];

  # Check if the correct attribute was asked
  if ($attr !~ /^(inet|nm|gw|bc|ns)$/) {
    return 1;
  }
  if ($attr ne "ns") {
    `ifconfig $if 2>/dev/null`;
    if ($? != 0) {
      return 2;
    }
  }
  # Check which method
  if ($attr eq "ns") {
    $attr = `cat /etc/resolv.conf | grep nameserver | grep -v "#" | head -n1 | awk '{print \$2}'`;
  } elsif ($attr eq "inet") {
    $attr = `ifconfig $if | grep "inet addr:" | cut -d":" -f2 | cut -d" " -f1`;
  } elsif ($attr eq "bc") {
    $attr = `ifconfig $if | grep "Bcast:" | cut -d":" -f3 | cut -d" " -f1`;
  } elsif ($attr eq "nm") {
    $attr = `ifconfig $if | grep "Mask:" | cut -d":" -f4`;
  } elsif ($attr eq "gw") {
    $attr = `route -n | grep UG | awk '{print \$2}'`;
  }
  chomp($attr);
  if ($attr eq "") {
    return 3;
  } else {
    return $attr;
  }
}

# 2.02 getnetconf
# Function to get the network configuration method
#sub getnetconf() {
#  my $netconf = "false";
#  while ($netconf eq "false") {
#    if (-e "$networkconf") {
#      $netconf = `cat $networkconf | grep "Method: " | cut -d" " -f2`;
#      chomp($netconf);
#      if (!$netconf =~ /^(dhcp|static)$/) {
#        $netconf = "false";
#      }
#    } else {
#      `$basedir/network_config first`;
#      $netconf = "false";
#    }
#  }
#  return $netconf;
#}

# 2.03 getsensor
# Function to get the sensor name
sub getsensor() {
  my ($sensor, $key, $file);
  opendir(BDIR, $basedir);
  while($file = readdir(BDIR)) {
    if (! -d $file) {
      if ($file =~ /sensor[0-9]+\.key$/) {
        ($sensor, $key) = split(/\./, $file);
        if ("$sensor" ne "") {
          return $sensor;
        }
      }
    }
  }
  return "false";
}

# 2.04 getif
# Function to get the active interface
# Returns interface name on success
# Returns false on failure
sub getif() {
  my ($found_if, @if_ar, $if, $checkif);
  $found_if = "none";
  open(DEVNET, "/proc/net/dev");
  while(<DEVNET>) {
    if ($_ =~ /(eth.:|tr.:)/) {
      @if_ar = split(/ +/, $_);
      @if_ar = split(/:/, $if_ar[1]);
      $if = $if_ar[0];
      $checkif = `ifconfig -a | grep -v UNSPEC | grep -A3 $if | grep "RUNNING" | wc -l`;
      chomp($checkif);
      if ($checkif != 0) {
        $found_if = $if;
      } else {
        $checkif = `mii-tool $if | grep negotiated | wc -l`;
        chomp($checkif);
        if ($checkif != 0) {
          $found_if = $if;
        }
      }
    }
  }
  close(DEVNET);
  chomp($found_if);
  if ($found_if ne "") {
    if ($found_if eq "none") {
      return "false";
    } else {
      return $found_if;
    }
  } else {
    return "false";
  }
  return "false";
}

# 2.05 getifip
# Function to get the IP address of the active interface.
sub getifip() {
  my ($if, $ipcheck, $ifip);
  $if = $_[0];
  chomp($if);
  if ($if eq "") {
    return "false";
  }
  $ipcheck = `ifconfig $if | grep -i "inet addr" | wc -l`;
  if ($ipcheck == 0) {
    return "false";
  } else {
    $ifip = `ifconfig $if | grep -i "inet addr" | cut -d":" -f2 | cut -d" " -f1`;
    chomp($ifip);
    return $ifip;
  }
  return "false";
}

# 2.06 getportstatus
# Function to check if the sensor can make a connection to the server with given port
# Dependencies: nmap
sub getportstatus() {
  my ($if, $port, $nmapcheck, $nmapcount, @nmapresult, $state);
  $if = $_[0];
  $port = $_[1];
  $nmapcheck = `nmap -e $if -p $port $server -P0 | grep $port`;
  chomp($nmapcheck);
  @nmapresult = split(/ +/, $nmapcheck);
  $nmapcount = @nmapresult;
  if ($nmapcount == 0) {
    return "Failed";
  } else {
    $state = $nmapresult[1];
    return $state;
#    if ($state eq "open") {
#      return "$state";
#    } else {
#      return "$state";
#    }
  }
  return "${r}False${n}";
}

# 2.07 getresolv
# Function to check if name resolving works.
# Dependencies: nslookup
sub getresolv() {
  my ($server, $chknslookup, @nslookup, $nscount);
  $server = $_[0];
  chomp($server);
  if ($server =~ /\b(([0-2]?\d{1,2}\.){3}[0-2]?\d{1,2})\b/) {
    return $server;
  } else {
    $chknslookup = `nslookup $server | grep "Address: "`;
    chomp($chknslookup);
    @nslookup = split(/ +/, $chknslookup);
    $nscount = @nslookup;
    if ($nscount == 0) {
      return "false";
    } else {
      return $nslookup[1];
    }
  }
  return "false";
}

# 2.08 getcerts
# Function to get the sensor certificates
# Dependencies: wget
# Returns sensor name on success
# Returns false on failure
sub getcerts() {
  my ($certfile, $sensor, $eof, $line, $chkclientconf, $fixclient, $if_ip, $vlanid, $ris, $risquery);
  $if_ip = $_[0];
  $vlanid = $_[1];
  chomp($if_ip);
  chomp($vlanid);
  $certfile = `mktemp -p $basedir`;
  chomp($certfile);
  `rm -f $certfile 2>/dev/null`;
  if (-r "$basedir/identifier.ris") {
    $ris = `cat $basedir/identifier.ris`;
    chomp($ris);
    $risquery = "&md5_ris=$ris";
  } else {
    $risquery = "";
  }
  `wget -q $wgetarg -O "$certfile" "$serverurl/cert.php?ip_localip=$if_ip&int_vlanid=$vlanid$risquery"`;
  printmsg("Retrieving sensor certificates:", $?);
  if ($? != 0) {
    `rm -f $certfile 2>/dev/null`;
    exit;
  }

  # Parsing the sensor name from the downloaded certificate file
  $sensor = `tail -n1 $certfile`;
  chomp($sensor);
  
  # Updating client.conf
  printmsg("Updating client.conf:", "info");
  open(CLIENT, ">> $basedir/client.conf");
  print CLIENT "ca $basedir/ca.crt\n";
  print CLIENT "key $basedir/$sensor.key\n";
  print CLIENT "cert $basedir/$sensor.crt\n";
  close(CLIENT);

  # Parsing the .key and .crt file from the downloaded certificate file
  printmsg("Parsing the certificates:", "info");
  open(PHP, "$certfile");
  open(KEY, "> $basedir/$sensor.key");
  open(CERT, "> $basedir/$sensor.crt");
  $eof = 0;
  while(<PHP>) {
    $line = $_;
    chomp($line);
    if ($line =~ /^EOF$/) {
      $eof++;
    } elsif ($eof == 0) {
      print KEY "$line\n";
    } elsif ($eof == 1) {
      print CERT "$line\n";
    } elsif ($eof == 2) {
      printmsg("Finished parsing certificates:", "info");
    } else {
      print "${r}Could not parse the following line:\n";
      print "$line${n}\n";
    }
  }
  close(PHP);
  close(KEY);
  close(CERT);

  # Finished parsing the certificate file
  $chkclientconf = chkclientconf();
  printmsg("Checking client.conf:", $chkclientconf);
  if ($chkclientconf != 0) {
    $fixclient = fixclientconf();
    printmsg("Fixing client.conf:", $fixclient);
  }
  `rm -f $certfile 2>/dev/null`;
  $sensor = getsensor();
  return $sensor;
}

#########################
# 3 MISC functions
#########################

# 3.01 prompt
# Function to prompt the user for input
sub prompt() {
  my ($promptstring, $defaultvalue);
  ($promptstring,$defaultvalue) = @_;
  if ($defaultvalue) {
    #print $promptstring, "[", $defaultvalue, "]: ";
    print $promptstring;
  } else {
    $defaultvalue = "";
    print $promptstring;
  }
  $| = 1;	# force a flush after our print
  $_ = <STDIN>;	# get the input from STDIN

  chomp;

  if ("$defaultvalue") {
    if ($_ eq "") {
      return $defaultvalue;
    } else {
      return $_;
    }
  } else {
    return $_;
  }
}

# 3.02 printmsg
# Function to print status message
sub printmsg() {
  my ($msg, $ec, $len, $tabcount, $tabstring);
  $msg = $_[0];
  chomp($msg);
  $ec = $_[1];
  chomp($ec);
  $len = length($msg);
  $tabcount = ceil((40 - $len) / 8);
  $tabstring = "\t" x $tabcount;
  if ("$ec" eq "0" || "$ec" eq "true") {
    print $msg . $tabstring . "[${g}OK${n}]\n";
  } elsif ($ec eq "false" || $ec eq "filtered") {
    print $msg . $tabstring . "[${r}Failed${n}]\n";
  } elsif ($ec eq "warning") {
    print $msg . $tabstring . "[${r}Warning${n}]\n";
  } elsif ($ec =~ /^[-]?(\d+)$/) {
    print $msg . $tabstring . "[${r}Failed (error: $ec)${n}]\n";
  } elsif ($ec eq "ignore") {
    print $msg . $tabstring . "[${y}ignore${n}]\n";
  } elsif ($ec eq "info") {
    print $msg . $tabstring . "[${y}info${n}]\n";
  } else {
    print $msg . $tabstring . "[${g}$ec${n}]\n";
  }
}

# 3.03 dossh
# Function to disable or enable the ssh daemon
# Dependencies: sshd
# Returns 0 if the action was succesful
# Returns 1 if the action was not succesful
sub dossh() {
  my $action = $_[0];
  if ($action eq "enable") {
    `/etc/init.d/ssh start`;
    if ($? == 0) {
      return 0;
    } else {
      return 1;
    }
  } elsif ($action eq "disable") {
    `killall sshd`;
    if ($? == 0) {
      return 0;
    } else {
      return 1;
    }
  } else {
    return 1;
  }
}

# 3.04 validip
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

# 3.05 fixclientconf
# Function to clean and fix the client.conf if possible
# Returns 0 if client.conf was succesfuly fixed
# Returns 1 if the sensor name could not be found
# Returns 2 if client.conf and client.conf.temp do not exist
# Returns 3 if the default template could not be copied
# Returns 4 if client.conf.temp was not found
# Returns 5 if the clientconf check failed
# Returns 6 for unknown error
sub fixclientconf() {
  my ($sensor, $chkclient, $temp, $count);
  $sensor = getsensor();
  if ($sensor eq "false") {
    return 1;
  }
  if (! -e "$basedir/client.conf") {
    if (! -e "$basedir/client.conf.temp") {
      return 2;
    } else {
      `cp $basedir/client.conf.temp $basedir/client.conf`;
      if ($? != 0) {
        return 3;
      }
    }
  } elsif (-e "$basedir/client.conf.temp") {
    `cp $basedir/client.conf.temp $basedir/client.conf`;
    if ($? != 0) {
      return 3;
    }
  } else {
    return 4;
  }
  open(CONF, ">> $basedir/client.conf");
  print CONF "ca $basedir/ca.crt\n";
  print CONF "cert $basedir/$sensor.crt\n";
  print CONF "key $basedir/$sensor.key\n";
  close(CONF);
  $chkclient = chkclientconf();
  if ($chkclient == 0) {
    return 0;
  } else {
    return 5;
  }
  return 6;
}

# 3.06 updatefile
# Function used by the update script to update a file with it's newer verison
# Returns 0 on success
# Returns 1 on failure
# Returns temporary filename if wait == 1
sub updatefile() {
  my ($touchnew, $touchsig, $serverfile, $wait);
  $serverfile = $_[0];
  $wait = $_[1];
  $touchsig = `mktemp -p $basedir`;
  chomp($touchsig);
  if ($? != 0) {
    return 1;
  }
  $touchnew = `mktemp -p $basedir`;
  chomp($touchnew);
  if ($? != 0) {
    return 1;
  }
  `wget -q $wgetarg -O $touchsig $serverurl/updates/${serverfile}.sig`;
  if ($? == 0) {
    `openssl smime -verify -text -inform SMIME -in $touchsig -out $touchnew -CAfile $basedir/scripts.crt 2>/dev/null`;
    if ($? == 0) {
      `rm -f $basedir/$serverfile`;
      `rm -f $touchsig`;
      if ($wait == 0) {
        `sed 's/\\r//' $touchnew > $basedir/$serverfile`;
        `rm -f $touchnew`;
        return 0;
      } else {
        return $touchnew;
      }
    } else {
      `rm -f $touchsig`;
      `rm -f $touchnew`;
      return 1
    }
  }
  return 1;
}

# 3.07 setiptables
# Function to set iptable rules
# Returns 0 on success
# Returns nonzero on failure
sub setiptables() {
  my ($dev);
  $dev = $_[0];
  `iptables -A OUTPUT -p TCP -m physdev --physdev-out $dev --dport 1194 -j DROP`;
  return $?;
}

# 3.08 setbridge
# Function to setup the bridge interface
# Returns 0 on success
# Returns nonzero on failure
sub setbridge() {
  my ($i, $chkdhclient, $enable_promisc, $br, $if, $tap, $netconf);
  $br = $_[0];
  $tap = $_[1];
  $if = $_[2];
  $netconf = $_[3];

  $i = 0;

  if ($netconf eq "dhcp") {
    $if_ip = &getifip($if);
    $if_gw = &getnetinfo("gw", $if);
    $if_nm = &getnetinfo("nm", $if);
    $if_bc = &getnetinfo("bc", $if);
  }

  # Creating and configuring bridge device
  `brctl addbr $br >/dev/null`;
  if ($? != 0 && $i == 0) { $i = 1; }
  `brctl addif $br $if >/dev/null`;
  if ($? != 0 && $i == 0) { $i = 2; }
  `brctl addif $br $tap >/dev/null`;
  if ($? != 0 && $i == 0) { $i = 3; }
  `brctl stp $br off >/dev/null`;
  if ($? != 0 && $i == 0) { $i = 4; }

  # Checking for active dhclient instances
  $chkdhclient = `ps -ef | grep -i "dhclient3 $if" | grep -v grep | wc -l`;
  if ($chkdhclient > 0) {
    `killall dhclient3 2>/dev/null`;
    if ($? != 0 && $i == 0) { $i = 5; }
  }

  if ($enable_promisc == 1) {
    `ifconfig $if 0.0.0.0 promisc up 2>/dev/null`;
    if ($? != 0 && $i == 0) { $i = 6; }
    `ifconfig $tap 0.0.0.0 promisc up 2>/dev/null`;
    if ($? != 0 && $i == 0) { $i = 7; }
  } else {
    `ifconfig $if 0.0.0.0 -promisc up 2>/dev/null`;
    if ($? != 0 && $i == 0) { $i = 8; }
    `ifconfig $tap 0.0.0.0 -promisc up 2>/dev/null`;
    if ($? != 0 && $i == 0) { $i = 9; }
  }
  
  if ($netconf ne "vlan") {
    `ifconfig $br $if_ip netmask $if_nm broadcast $if_bc`;
    if ($? != 0 && $i == 0) { $i = 10; }
    `route add -net default gw $if_gw >/dev/null`;
    if ($? != 0 && $i == 0) { $i = 11; }
  }
  return $i;
}

# 3.09 validvlanid
# Function to check if the vlan id is valid
# Returns 0 if not valid or exceeded
# Returns 1 if ok
sub validvlanid() {
  my ($vlanid);
  $vlanid = $_[0];
  if ($vlanid =~ /^(\d{0,4})$/) {
    if ($vlanid > 0 && $vlanid < 4097) {
      return 0;
    } else {
      return 1; 
    }
  } else {
    return 1; 
  }
}

# 3.10 validvlancount
# Function to check if the vlan id is valid
# Returns 0 if valid vlancount
# Returns 1 if invalid vlancount
sub validvlancount() {
  my ($vlancount);
  $vlancount = $_[0];
  chomp($vlancount);
  if ($vlancount =~ /^(\d{0,1})$/) {
    if ($vlancount > 0 && $vlancount < 9) {
      return 0;
    } else {
      return 1; 
    }
  } else {
    return 1; 
  }
}

# 3.11 sleeptimer
# Function to sleep for a certain amount of seconds
# while displaying progress
sub sleeptimer() {
  my ($msg, $count, $len, $tabcount, $tabstring);
  $msg = $_[0];
  $count = $_[1];
  chomp($msg);
  chomp($count);
  $len = length($msg);
  $tabcount = ceil((40 - $len) / 8);
  $tabstring = "\t" x $tabcount;
  print $msg . $tabstring . "[";
  for (1 ... ($count - 1)) {
    print ".";
    sleep 1;
  }
  print "${g}OK${n}]\n";
  return 0;
}

# 3.12 printdelay
# Function to print status message
sub printdelay() {
  my ($msg, $len, $tabcount, $tabstring);
  $msg = $_[0];
  chomp($msg);
  $len = length($msg);
  $tabcount = ceil((40 - $len) / 8);
  $tabstring = "\t" x $tabcount;
  print $msg . $tabstring;
  return 0;
}

# 3.13 printresult
# Function to print the result of an action.
# Used along with printdelay
sub printresult() {
  my ($ec);
  $ec = $_[0];
  chomp($ec);
  if ("$ec" eq "0") {
    print "[${g}OK${n}]\n";
  } elsif ($ec eq "false" || $ec eq "filtered") {
    print "[${r}Failed${n}]\n";
  } elsif ($ec =~ /^[-]?(\d+)$/) {
    print "[${r}Failed (error: $ec)${n}]\n";
  } elsif ($ec eq "ignore") {
    print "[${y}ignore${n}]\n";
  } elsif ($ec eq "info") {
    print "[${y}info${n}]\n";
  } else {
    print "[${g}$ec${n}]\n";
  }
  return 0;
}

# 3.14 clientconftemp
# Function to create client.conf.temp from the 
# existing client.conf
# Returns 0 on success
# Returns 1 on failure
sub clientconftemp() {
  if (-e "$basedir/client.conf") {
    $count = `wc -l $basedir/client.conf`;
    chomp($count);
    if ($count > 0) {
      `cat $basedir/client.conf | grep -v ^ca.*ca\.crt\$ | grep -v ^key.*sensor.*\.key\$ | grep -v ^cert.*sensor.*\.crt\$ > $basedir/client.conf.temp`;
      if ($? == 0) {
        return 0;
      } else {
        return 1;
      }
    } else {
      return 1;
    }
  } else {
    return 1;
  }
  if ($? == 0) {
    return 0;
  } else {
    return 1;
  }
  return 1;
}

# 3.15 dec2bin
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

# 3.16 bin2dec
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

# 3.17 bc
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

# 3.18 network
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
  $temp = substr($bina, length($binn), (32 - length($binn)));
  $temp =~ s/1/0/g;
  $binn = $binn . $temp;
  $net = &bin2dec($binn);
  return $net;
}

# 3.19 cidr
# Function to convert a dotted decimal netmask to CIDR notation
# Returns CIDR notation on success
# Returns false on failure
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

# 3.20 gw
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

# 3.21 upplstatus
# Function to update the tunnel status in the status file
# Returns 0 on success
# Returns non-zero on failure
sub upplstatus() {
  my ($status, $tmpfile, $tunnel, $i, $try, $oldaction);
  $tunnel = $_[0];
  $status = $_[1];
  $tmpfile = $_[2];
  $i = 0;
  $try = `grep "$tunnel:" $basedir/tunnel.status | awk -F":" '{print \$3}'`;
  $oldaction = `grep "$tunnel:" $basedir/tunnel.status | awk -F":" '{print \$2}'`;
  chomp($try);
  chomp($oldaction);
  if ("$try" eq "" || $oldaction eq "DONE") {
    $try = 0;
  }
  if ($oldaction eq "SLEEP") {
    $try++;
  }
  `sed '/^$tunnel:.*\$/d' $basedir/tunnel.status > $tmpfile`;
  if ($? != 0) { $i++; }
  `mv $tmpfile $basedir/tunnel.status`;
  if ($? != 0) { $i++; }
  `echo $tunnel:$status:$try >> $basedir/tunnel.status`;
  if ($? != 0) { $i++; }
  return $i;
}

# 3.22 startdhcp
# Function to start the DHCP client for a given interface
# Returns exit code
sub startdhcp() {
  my ($if, $vlanid, $ec, $dhcplib, $dhcprun);
  $dhcplib = "/var/lib/dhcp3";
  $dhcprun = "/var/run/dhcp3";
  $if = $_[0];
  chomp($if);
  if ($_[1]) {
    $vlanid = $_[1];
    chomp($vlanid);
  }
  if ($vlanid ne "") {
    `dhclient3 -lf $dhcplib/dhcp$vlanid.lease -sf $basedir/dhclient-script-vlan -pf $dhcprun/dhcp$vlanid.pid $if 2>/dev/null`;
  } else {
    `dhclient3 -lf $dhcplib/$if.lease $if 2>/dev/null`;
  }
  return $?;
}

return "true";
