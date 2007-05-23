#!/usr/bin/perl -w

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
  # Update Tap info to the database for the current $sensor.
  $sql = "SELECT id FROM sensors WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  # Get the tap ip address of tap device ($tap) from the query result.
  @row = $sth->fetchrow_array;
  $sensorid = $row[0];
  if ("$sensorid" eq "") {
    exit 1;
  }
} else {
  exit 1;
}

# Initialize the scripts arp cache
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
$refresh_time = $ts + $c_arp_static_refresh;

##################
# Getting interface info
##################
$ifip = getifip($tap);
$ifmask = getifmask($tap);
$ifmin = ip2long(network($ifip, $ifmask));
$ifmax = ip2long(bc($ifip, $ifmask));

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

    if ($ts > $refresh_time) {
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
      $refresh_time = $ts + $c_arp_static_refresh;
    }

    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data});
    $arp_opcode = $arp_obj->{opcode};
    if ($arp_opcode == 1) {
      #######################
      # (2.1.1) ARP Query
      #######################
      $arp_source_mac = colonmac($arp_obj->{sha});
      $arp_source_ip = hextoip($arp_obj->{spa});
      $arp_dest_mac = colonmac($arp_obj->{tha});
      $arp_dest_ip = hextoip($arp_obj->{tpa});

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
