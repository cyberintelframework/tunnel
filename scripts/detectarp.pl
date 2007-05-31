#!/usr/bin/perl

########################################
# ARP detection module                       
# SURFnet IDS                          
# Version 1.04.01                      
# 16-05-2007                           
# Kees Trippelvitz & Jan van Lith
########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Author Kees Trippelvitz & Jan van Lith                                                #
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

#####################
# Changelog:
# 1.04.01 Initial release
#####################

##################
# Modules used
##################
require Net::Pcap;
use Net::PcapUtils;
use NetPacket::IP;
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use NetPacket::Ethernet qw(:types);
use NetPacket::Ethernet qw(:strip);
use NetPacket::ARP;
use DBI;
use Time::localtime;
use POSIX;
use Socket;
use Net::SMTP;
use MIME::Lite;
use GnuPG qw( :algo );

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
$tap = $ARGV[0];

$logfile = $c_logfile;
$logfile =~ s|.*/||;
if ($c_logstamp == 1) {
  $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  $year = localtime->year() + 1900;
  if ( ! -d "$c_surfidsdir/log/$day$month$year" ) {
    mkdir("$c_surfidsdir/log/$day$month$year");
  }
  if ( ! -d "$c_surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$c_surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$c_surfidsdir/log/$day$month$year/$tap/$logfile";
} else {
  $logfile = "$c_surfidsdir/log/$logfile";
}

$argcount = @ARGV;
if ($argcount == 0) {
  exit 1;
}

##################
# Functions
##################
%ethernettypes = (
	12 => "PUP",
	2048 => "IP",
	2054 => "ARP",
	24578 => "Remote Console",
	32821 => "RARP",
	33024 => "802.1q",
	34525 => "IPv6",
	34915 => "PPPOE discovery",
	34916 => "PPPOE session",
);

%iptypes = (
	1 => "ICMP",
	2 => "IGMP",
	6 => "TCP",
	17 => "UDP",
	41 => "IPv6",
	103 => "PIM (multicast)",
);

##################
# Main script
##################

printlog("Starting detectarp.pl!");

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

# Getting the sensor ID
if ("$dbconn" ne "false") {
  $sql = "SELECT id, organisation, netconf FROM sensors WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  @row = $sth->fetchrow_array;
  $sensorid = $row[0];
  $org = $row[1];
  $netconf = $row[2];
  if ("$sensorid" eq "") {
    exit 1;
  }
  if ("$org" eq "") {
    exit 1;
  }
} else {
  exit 1;
}

# Get the info needed for the mailreport stuff
$sql = "SELECT login.email, login.gpg FROM report_content, login ";
$sql .= " WHERE login.id = report_content.user_id AND report_content.sensor_id = $sensorid AND report_content.template = 5 AND report_content.active = TRUE";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $email = $row[0];
  $gpg = $row[1];
  print "Loading mailreports: $email - $gpg\n";
  $arp_mail{"$email"} = $gpg;
}

# Initialize the scripts arp cache, alert and static hashes
%arp_cache = ();
%arp_alert = ();
%arp_static = ();

printlog("Filling arp cache!");
#### ARP CACHE ####
# Filling the local scripts arp cache
$sql = "SELECT mac, ip FROM arp_cache WHERE sensorid = $sensorid";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $db_mac = $row[0];
  $db_ip = $row[1];
  $arp_cache{"$db_mac"} = $db_ip;
}
$ts = time();
$cache_refresh = $ts + $c_arp_cache_refresh;

printlog("Filling static arp list!");
#### ARP STATIC ####
# Filling the local scripts static arp list
$sql = "SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $db_mac = $row[0];
  $db_ip = $row[1];
  $arp_static{"$db_ip"} = $db_mac;
}
$ts = time();
$static_refresh = $ts + $c_arp_static_refresh;

##################
# Getting interface info
##################
$ifip = getifip($tap);
$ifmask = getifmask($tap);
$ifmin = ip2long(network($ifip, $ifmask));
$ifmax = ip2long(bc($ifip, $ifmask));
if ($netconf eq "dhcp" || $netconf eq "vland") {
  $gw = `cat /var/lib/dhcp3/$tap.leases | grep routers | tail -n1 | awk '{print \$3}' | awk -F\\; '{print \$1}'`;
  chomp($gw);
  if ("$gw" eq "") {
    $gw = gw($ifip, $ifmask);
  }
} else {
  $gw = gw($ifip, $ifmask);
}

##################
# Checking the gateway IP/MAC pair.
##################

$sql = "SELECT mac FROM arp_static WHERE sensorid = $sensorid AND ip = '$gw'";
$sth = $dbh->prepare($sql);
$er = $sth->execute();
@row = $sth->fetchrow_array;
$db_mac = $row[0];

`arping -h 2>/dev/null`;
if ($? == 0) {
  %maclist = ();
  open(ARPING, "arping -r -i $tap -c 4 $gw | ");
  while (<ARPING>) {
    $mac = $_;
    chomp($mac);
    $maclist{"$mac"} = 0;
  }
  close(ARPING);
  $count = keys(%maclist);
  if ($count == 1) {
    if ("$db_mac" eq "") {
      # Static ARP entry for the gateway not yet present. Add it.
      printlog("Adding static ARP entry for the gateway!");

      $sql = "INSERT INTO arp_static (mac, ip, sensorid) VALUES ('$mac', '$gw', $sensorid)";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
    } elsif ("$db_mac" ne "$mac") {
      # Static ARP entry for the gateway present, but with a different MAC address. Update it.
      printlog("Updating static ARP entry for the gateway!");

      $sql = "UPDATE arp_static SET mac = '$mac' WHERE sensorid = $sensorid AND ip = '$gw'";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
    }
  } else {
    # Gateway returned multiple MAC addresses. Network is possibly poisoned!
    if ("$db_mac" ne "") {
      # Static ARP entry present in the database.
      if (exists $maclist{"$db_mac"}) {
        for my $key ( keys %maclist ) {
          if ("$key" ne "$db_mac") {
            $poisonmac = $key;
            add_arp_alert($db_mac, $poisonmac, $gw, $sensorid);
          }
        }
      }
    }
  }
}

##################
# TCPdump part (handles most stuff)
##################

# Setting up the pcap options
my %args = (
        SNAPLEN => 100,         # Num bytes to capture from packet
        PROMISC => 1,           # Operate in promiscuous mode?
        TIMEOUT => 1000,        # Read timeout (ms)
        NUMPACKETS => -1,       # Pkts to read (-1 = loop forever)
        FILTER => '',           # Filter string
        USERDATA => '',         # Passed as first arg to callback fn
        SAVEFILE => '',         # Default save file
        DEV => "$tap",              # Network interface to open
        );

# Putting the interface on promiscuous mode to catch more traffic
`ifconfig $tap promisc up`;
printlog("Setting interface in promisc", $?);

$i = 0;
$e = 0;

# Function to handle the sniffing
sub filter_packets {
  my ($userdata, $header, $pckt) = @_;
  my $eth_obj = NetPacket::Ethernet->decode($pckt);
  $eth_type = $eth_obj->{type};

  #########################################
  # (1) IP Protocol
  #########################################

  if ($eth_obj->{type} == ETH_TYPE_IP) {
    # IP packet
    $ip_obj = NetPacket::IP->decode($eth_obj->{data});
    $proto = $ip_obj->{proto};

    if ($proto == 1) {
      # ICMP protocol detected
    } elsif ($proto == 2) {
      # IGMP protocol detected
    } elsif ($proto == 6) {
      # TCP protocol detected
      my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
      $flags = $tcp_obj->{flags};
    } elsif ($proto == 17) {
      # UDP protocol detected
    } elsif ($proto == 41) {
      # IPv6 protocol detected
    }
  }
  elsif ($eth_obj->{type} == ETH_TYPE_SNMP) {
#    print "ETH_TYPE_SNMP\n";
  }
  elsif ($eth_obj->{type} == ETH_TYPE_ARP) {
    $ts = time();

    if ($ts > $static_refresh) {
      %arp_static = ();

      #### ARP STATIC ####
      # Filling the local scripts static arp list
      $sql = "SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();

      while (@row = $sth->fetchrow_array) {
        $db_mac = $row[0];
        $db_ip = $row[1];
        $arp_static{"$db_ip"} = $db_mac;
      }
      $static_refresh = $ts + $c_arp_static_refresh;
    }

    if ($ts > $cache_refresh) {
      #### ARP CACHE ####
      $sql = "SELECT COUNT(id) as total FROM arp_cache WHERE sensorid = $sensorid";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
      @row = $sth->fetchrow_array;
      $count = $row[0];
      if ($count == 0) {
        %arp_cache = ();
      }
      $cache_refresh = $ts + $c_arp_static_refresh;
    }

    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data});
    $arp_opcode = $arp_obj->{opcode};
#    $eth_data = unpack('H*', $eth_obj->{data});
#    print "ETHDATA: $eth_data\n";
#    $data = unpack('A*', $header);
#    Dumper($data);
#    print "DATA: $data\n";

    if ($arp_opcode == 1) {
      #######################
      # (2.1.1) ARP Query
      #######################
      $arp_source_mac = colonmac($arp_obj->{sha});
      $arp_source_ip = hextoip($arp_obj->{spa});
      $arp_dest_mac = colonmac($arp_obj->{tha});
      $arp_dest_ip = hextoip($arp_obj->{tpa});

      print "ARPQUERY: $arp_source_mac ($arp_source_ip) -> $arp_dest_mac ($arp_dest_ip)\n";

      $check = add_arp_cache($arp_source_mac, $arp_source_ip, $sensorid);
      $check = chk_static_arp($arp_source_mac, $arp_source_ip, $sensorid);
    } elsif ($arp_opcode == 2) {
      #######################
      # (2.1.1) ARP Reply
      #######################
      $arp_source_mac = colonmac($arp_obj->{sha});
      $arp_source_ip = hextoip($arp_obj->{spa});
      $arp_dest_mac = colonmac($arp_obj->{tha});
      $arp_dest_ip = hextoip($arp_obj->{tpa});

      print "ARPREPLY: $arp_source_mac ($arp_source_ip) -> $arp_dest_mac ($arp_dest_ip)\n";

      $check = add_arp_cache($arp_dest_mac, $arp_dest_ip, $sensorid);
      $check = chk_static_arp($arp_dest_mac, $arp_dest_ip, $sensorid);

      # Reply source check
      $arp_source_ip_long = ip2long($arp_source_ip);
      if ($arp_source_ip_long > $ifmin && $ifmax > $arp_source_ip_long) {
        $check = add_arp_cache($arp_source_mac, $arp_source_ip, $sensorid);
        $check = chk_static_arp($arp_source_mac, $arp_source_ip, $sensorid);
      }
    }
  }
}

# Call the filter_arp function for packets received with type "ARP"
Net::PcapUtils::loop(\&filter_packets, %args);

printlog("--------Finished detectarp.pl--------");
