#!/usr/bin/perl -w

########################################
# TCPdump script                       
# SURFnet IDS                          
# Version 1.02.01                      
# 26-06-2006                           
# Kees Trippelvitz                     
########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Author Kees Trippelvitz                                                               #
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

##################
# Code index
#
# (1)		IP Protocol
# (2)		ARP Protocol
# (2.1)		ARP Query
# (2.1.1)	ARP Query: ARP Stats
# (2.1.2) 	ARP Query: Info
# (2.1.3) 	ARP Query: Static check
# (2.1.4) 	ARP Query: Cache check
# (2.2) 	ARP Reply
# (2.2.1) 	ARP Reply: ARP Stats
# (2.2.2)       ARP Reply: Info
# (2.2.3)	ARP Reply: Static check
# (2.2.4)	ARP Reply: Cache check
##################

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

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
$tap = $ARGV[0];

$argcount = @ARGV;
if ($argcount == 0) {
  exit 1;
}

##################
# Functions
##################
sub hextoip {
  my ($hex) = @_;
  my $P1 = hex(substr($hex,0,2));
  my $P2 = hex(substr($hex,2,2));
  my $P3 = hex(substr($hex,4,2));
  my $P4 = hex(substr($hex,6,2));
  my $quad = "$P1.$P2.$P3.$P4";
  return $quad;
}

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

##################
# Main script
##################
# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

# Get the sensor info
$sth = $dbh->prepare("SELECT id, keyname, arp_threshold_perc FROM sensors WHERE tap = '$tap'");
$execute_result = $sth->execute();
@row = $sth->fetchrow_array;
$sensorid = $row[0];
$sensor = $row[1];
$arp_threshold_perc = $row[2];

# Check if there's a record present in arp_stats, if not, add it.
$sth = $dbh->prepare("SELECT count(id) as total FROM arp_stats WHERE sensorid = $sensorid");
$execute_result = $sth->execute();
@row = $sth->fetchrow_array;
$numrows_arpstats = $row[0];
if ($numrows_arpstats == 0) {
  $sql_insert = "INSERT INTO arp_stats (timestamp, sensorid, replies, queries, query_time, reply_time, avg_reply, avg_query) VALUES (0, $sensorid, 0, 0, 0, 0, 0, 0)";
  $sth = $dbh->prepare($sql_insert);
  $execute_result = $sth->execute();
}

# Filling the arp_cache hash
$sth_cache = $dbh->prepare("SELECT mac, ip FROM arp_cache WHERE sensorid = $sensorid");
$result_cache = $sth_cache->execute();
while (@row_cache = $sth_cache->fetchrow_array) {
  $mac = $row_cache[0];
  $ip = $row_cache[1];
  $i++;
  $arp_cache{"$mac"} = "$ip";
}

# Filling the arp_static hash
$sth_static = $dbh->prepare("SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid");
$result_static = $sth_static->execute();
while (@row_static = $sth_static->fetchrow_array) {
  $mac = $row_static[0];
  $ip = $row_static[1];
  $i++;
  $arp_static{"$ip"} = "$mac";
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

$query_ts = time();
$reply_ts = time();

$query_count = 0;
$reply_count = 0;

$arp_mon_stats_period_in_seconds = $arp_mon_stats_period * 60;
#$i = 0;
#$e = 0;

# Function to handle the sniffing
sub filter_packets {
  my ($userdata, $header, $pckt) = @_;

  ##########################
  # Ethernet types
  # 12   (PUP)
  # 2048  (IP)
  # 2054  (ARP)
  # 32821 (RARP)
  # 33024 (802.1q)
  # 34525 (IPv6)
  # 34915 (PPPOE discovery)
  # 34916 (PPPOE session)
  ##########################

  # 19 => 30
  # 50 => 154
  # 2048 => 38
  # 2054 => 262
  # 24578 => 1
  # 34525 => 15

  my $eth_obj = NetPacket::Ethernet->decode($pckt);
  $eth_type = $eth_obj->{type};
  $eth_stats{"$eth_type"}++;
#  $e++;
#  print "E: $e\n";
#  if ($e == 100) {
#    print "---------- Ethernet dump ----------\n";
#    for my $key ( keys %eth_stats ) {
#      my $value = $eth_stats{$key};
#      print "$key => $value\n";
#    }
#    $e = 0;
#  }
#  if ($eth_type == 34525) {
#    print "Ethernet type IPv6 detected\n";
#  }

  #########################################
  # (1) IP Protocol
  #########################################

  if ($eth_obj->{type} == ETH_TYPE_IP) {
    # IP packet
    $ip_obj = NetPacket::IP->decode($eth_obj->{data});
#    $i++;
    $proto = $ip_obj->{proto};

    ##########################
    # IP protocol numbers
    # 1 = ICMP
    # 2 = IGMP
    # 6 = TCP
    # 17 = UDP
    # 41 = IPv6
    # 103 = PIM (multicast)
    ##########################

    $ip_stats{"$proto"}++;
    if ($proto == 1) {
      # ICMP protocol detected
    }
    elsif ($proto == 2) {
      # IGMP protocol detected
    }
    elsif ($proto == 6) {
      # TCP protocol detected
      my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
      $flags = $tcp_obj->{flags};
    }
    elsif ($proto == 17) {
      # UDP protocol detected
    }
    elsif ($proto == 41) {
      print "IP protocol IPv6 detected\n";
    }
#    print "I: $i\n";
#    if ($i == 100) {
#      print "---------- IP dump ----------\n";
#      for my $key ( keys %ip_stats ) {
#        my $value = $ip_stats{$key};
#        print "$key => $value\n";
#      }
#      $i = 0;
#    }
  }

  #########################################
  # (2) ARP Protocol
  #########################################

  elsif ($eth_obj->{type} == ETH_TYPE_ARP) {
    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
    my $arp_opcode = $arp_obj->{opcode};
    #######################
    # (2.1) ARP Query
    #######################
    if ($arp_opcode == 1) {
      #######################
      # (2.1.1) ARP Query: ARP Stats
      #######################
      $query_count++;
      $time = time();
      $threshold_query_time = $time - $query_ts;
      print "TS: $threshold_query_time\n";
      if ($threshold_query_time >= $arp_mon_stats_period_in_seconds) {
        $timestamp = time();

        # Get ARP query stats
        $sql_getstats = "SELECT queries, query_time FROM arp_stats WHERE sensorid = $sensorid";
        $sth_getstats = $dbh->prepare($sql_getstats);
        $result_getstats = $sth_getstats->execute();
        @row_getstats = $sth_getstats->fetchrow_array;
        $db_queries = $row_getstats[0];
        $db_query_time = $row_getstats[1];

        # Calculate new total queries and time measured
        $total_count = $query_count + $db_queries;
        $total_time = $arp_mon_stats_period + $db_query_time;

        # Calculating total average queries per $arp_mon_stats_period minutes
        $total_avg = ceil($total_count / ($total_time / $arp_mon_stats_period));

        $sql_insert = "UPDATE arp_stats SET timestamp = $timestamp, queries = $total_count, query_time = $total_time, avg_query = $total_avg WHERE sensorid = $sensorid";
        $threshold_query_count = ($total_avg * $arp_threshold_perc) / 100;
        if ($query_count > $threshold_query_count) {
          # Threshold was exceeded
          $sql_log = "INSERT INTO arp_log_stats (timestamp, sensorid, threshold, average, count, time, type) VALUES ($timestamp, $sensorid, $threshold_query_count, $total_avg, $query_count, $arp_mon_stats_period, $arp_opcode)";
          $sth_log = $dbh->prepare($sql_log);
          $execute_result = $sth_log->execute();
        }

        # Resetting some counters
        $query_ts = time();
        $query_count = 0;

        # Updating arp stats for arp_cache
        for $stats_mac ( keys %arp_stats_query ) {
          $stats_count = $arp_stats_query{"$stats_mac"};
          $sql_count = "UPDATE arp_cache SET query_count = $stats_count WHERE mac = '$stats_mac'";
          $sth_count = $dbh->prepare($sql_count);
          $result_count = $sth_count->execute();
          $arp_stats_query{"$stats_mac"} = 0;
        }

        # Updating the arp_static hash
        $sth_static = $dbh->prepare("SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid");
        $result_static = $sth_static->execute();
        while (@row_static = $sth_static->fetchrow_array) {
          $mac = $row_static[0];
          $ip = $row_static[1];
          $i++;
          $arp_static{"$ip"} = "$mac";
        }
      }

      #######################
      # (2.1.2) ARP Query: Info
      #######################
      $mac = colonmac($arp_obj->{sha});
      $ip = hextoip($arp_obj->{spa});

      $timestamp = time();
      $arp_stats_query{"$mac"}++;

      #######################
      # (2.1.3) ARP Query: Static check
      #######################
      if (exists $arp_static{"$ip"}) {
        # MAC address exists in the static ARP monitor list
        $static_mac = $arp_static{"$ip"};
        if ("$mac" ne "$static_mac") {
          # The MAC logged does not match the static MAC from the monitoring list.
          $sql_insert = "INSERT INTO arp_log (timestamp, ip, old_mac, new_mac, sensorid, type) VALUES ($timestamp, '$ip', '$static_mac', '$mac', $sensorid, 3)";
          $sth = $dbh->prepare($sql_insert);
          $execute_result = $sth->execute();
        }
      }

      #######################
      # (2.1.4) ARP Query: Cache check
      #######################
      if (exists $arp_cache{"$mac"}) {
        # MAC address exists in the ARP cache
        $cache_ip = $arp_cache{"$mac"};
        if ("$ip" ne "$cache_ip") {
          # MAC address has a new IP address.
          $sql_update = "UPDATE arp_cache SET timestamp = '$timestamp', ip = '$ip' WHERE mac = '$mac' AND sensorid = $sensorid";
          $sth = $dbh->prepare($sql_update);
          $execute_result = $sth->execute();
        }
      } else {
        # MAC - IP pair not yet in the arp_cache. Insert it.
        $arp_cache{"$mac"} = "$ip";
        $sql_insert = "INSERT INTO arp_cache (timestamp, mac, ip, sensorid) VALUES ($timestamp, '$mac', '$ip', $sensorid)";
        $sth = $dbh->prepare($sql_insert);
        $execute_result = $sth->execute();
      }
    #######################
    # (2.2) ARP Reply
    #######################
    } elsif ($arp_opcode == 2) {
      #######################
      # (2.2.1) ARP Reply: ARP Stats
      #######################
      $reply_count++;
      $time = time();
      $threshold_reply_time = $time - $reply_ts;
      if ($threshold_reply_time >= $arp_mon_stats_period_in_seconds) {
        $timestamp = time();

        # Get ARP query stats
        $sql_getstats = "SELECT replies, reply_time FROM arp_stats WHERE sensorid = $sensorid";
        $sth_getstats = $dbh->prepare($sql_getstats);
        $result_getstats = $sth_getstats->execute();
        @row_getstats = $sth_getstats->fetchrow_array;
        $db_replies = $row_getstats[0];
        $db_reply_time = $row_getstats[1];

        # Calculate new total queries and time measured
        $total_count = $reply_count + $db_replies;
        $total_time = $arp_mon_stats_period + $db_reply_time;

        # Calculating total average queries per $arp_mon_stats_period minutes
        $total_avg = ceil($total_count / ($total_time / $arp_mon_stats_period));

        $sql_insert = "UPDATE arp_stats SET timestamp = $timestamp, replies = $total_count, reply_time = $total_time, avg_reply = $total_avg WHERE sensorid = $sensorid";
        $threshold_reply_count = ($total_avg * $arp_threshold_perc) / 100;

        if ($reply_count > $threshold_query_count) {
          # Threshold was exceeded
          $sql_log = "INSERT INTO arp_log_stats (timestamp, sensorid, threshold, average, count, time, type) VALUES ($timestamp, $sensorid, $threshold_reply_count, $total_avg, $reply_count, $arp_mon_stats_period, $arp_opcode)";
          $execute_result = $sth_log->execute();
        }

        # Resetting some counters
        $reply_ts = time();
        $reply_count = 0;

        # Updating arp stats for arp_cache
        for $stats_mac ( keys %arp_stats_reply ) {
          $stats_count = $arp_stats_reply{"$stats_mac"};
          $sql_count = "UPDATE arp_cache SET reply_count = $stats_count WHERE mac = '$stats_mac'";
          $sth_count = $dbh->prepare($sql_count);
          $result_count = $sth_count->execute();
          $arp_stats_reply{"$stats_mac"} = 0;
        }
      }

      #######################
      # (2.2.2) ARP Reply: Info
      #######################
      $src_mac = $arp_obj->{sha};
      $src_ip = hextoip($arp_obj->{spa});
      $dst_mac = $arp_obj->{tha};
      $dst_ip = hextoip($arp_obj->{tpa});

      $timestamp = time();

      $arp_stats_reply{"$mac"}++;

      #######################
      # (2.2.3) ARP Reply: Static check
      #######################
      if (exists $arp_static{"$ip"}) {
        # MAC address exists in the static ARP monitor list
        $static_mac = $arp_static{"$ip"};
        if ("$mac" ne "$static_mac") {
          # The MAC logged does not match the static MAC from the monitoring list.
          $sql_insert = "INSERT INTO arp_log (timestamp, ip, old_mac, new_mac, sensorid, type) VALUES ($timestamp, '$ip', '$static_mac', '$mac', $sensorid, 3)";
          $sth = $dbh->prepare($sql_insert);
          $execute_result = $sth->execute();
        }
      }

      #######################
      # (2.2.4) ARP Reply: Cache check
      #######################
      if (exists $arp_cache{"$mac"}) {
        # MAC address exists in the ARP cache
        $cache_ip = $arp_cache{"$mac"};
        if ("$ip" ne "$cache_ip") {
          # MAC address has a new IP address.
          $sql_update = "UPDATE arp_cache SET timestamp = '$timestamp', ip = '$ip' WHERE mac = '$mac' AND sensorid = $sensorid";
          $sth = $dbh->prepare($sql_update);
          $execute_result = $sth->execute();
        }
      } else {
        # MAC - IP pair not yet in the arp_cache. Insert it.
        $arp_cache{"$mac"} = "$ip";
        $sql_insert = "INSERT INTO arp_cache (timestamp, mac, ip, sensorid) VALUES ($timestamp, '$mac', '$ip', $sensorid)";
        $sth = $dbh->prepare($sql_insert);
        $execute_result = $sth->execute();
      }
    }
  }
  elsif ($eth_obj->{type} == ETH_TYPE_SNMP) {
    print "ETH_TYPE_SNMP\n";
  }
}

# Call the filter_arp function for packets received with type "ARP"
Net::PcapUtils::loop(\&filter_packets, %args);
