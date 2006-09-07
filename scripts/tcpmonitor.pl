#!/usr/bin/perl -w

########################################
# IDMEF script for IDS server database #
# SURFnet IDS                          #
# Version 1.02.02                      #
# 12-04-2006                           #
# Jan van Lith & Kees Trippelvitz      #
########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
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
# Modules used
##################
use DBI;
use Time::localtime;
use Time::Local;
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

##################
# Main script
##################

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

# Get the sensor info
$sth = $dbh->prepare("SELECT id, keyname FROM sensors WHERE tap = '$tap'");
$execute_result = $sth->execute();
@row = $sth->fetchrow_array;
$sensorid = $row[0];
$sensor = $row[1];

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

# Putting the interface on promiscuous mode to catch more traffic
`ifconfig $tap promisc up`;

$query_ts = time();
$reply_ts = time();

$query_count = 0;
$reply_count = 0;

$arp_mon_stats_period_in_seconds = $arp_mon_stats_period * 60;

open (TCPDUMP, "tcpdump -enl -i $tap arp |") || die "Can't popen tcpdump\n";

while(<TCPDUMP>) {
  $line = $_;
  if ($line =~ /.*arp who-has.*/) {

    #######################
    # ARP stats
    #######################
    $query_count++;
    $time = time();
    $threshold_query_time = $time - $query_ts;
    print "TIME: $threshold_query_time\n";
    if ($threshold_query_time >= $arp_mon_stats_period_in_seconds) {
      # Loading the arp_stats module
      $ec = system "/opt/surfnetids/scripts/mod_arp_stats.pl", "$tap", "$sensorid", "$query_count", "query";

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
    # Pattern matching on the tcpdump line
    if ($line =~ /.*\(..:..:..:..:..:..\).*/) {
      ($time, $mac, $op, $dst, $ether, $arp, $hex, $len, $lenv, $arp, $action, $src_ip, $foo, $tell, $ip) = split(' ');
    } else {
      ($time, $mac, $op, $dst, $ether, $arp, $hex, $len, $lenv, $arp, $action, $src_ip, $tell, $ip) = split(' ');
    }
    $timestamp = time();
    
    $arp_stats_query{"$mac"}++;

    #######################
    # ARP static check
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
    # ARP cache check
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
  elsif ($line =~ /.*arp reply.*/) {

    #######################
    # ARP stats
    #######################
    $reply_count++;
    $time = time();
    $threshold_reply_time = $time - $reply_ts;
    if ($threshold_reply_time >= $arp_mon_stats_period_in_seconds) {
      # Loading the arp_stats module
      $ec = system "/opt/surfnetids/scripts/mod_arp_stats.pl", "$tap", "$sensorid", "$query_count", "$type";

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

    ($time, $src, $op, $dst, $ether, $arp, $hex, $len, $lenv, $arp, $action, $ip, $isat, $mac) = split(' ');
    $timestamp = time();

    $arp_stats_reply{"$mac"}++;

    #######################
    # ARP static check
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
    # ARP cache check
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
