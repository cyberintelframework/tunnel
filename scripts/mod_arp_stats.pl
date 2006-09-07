#!/usr/bin/perl

###########################################
# Ethernet monitor module for ARP queries #
# SURFnet IDS                             #
# Version 1.02.01                         #
# 13-06-2006                              #
# Kees Trippelvitz                        #
###########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Kees Trippelvitz                                                              #
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
$sensorid = $ARGV[1];
$count = $ARGV[2];
$type = $ARGV[3];

$argcount = @ARGV;
print "ARGV: $argcount\n";

if ($argcount != 4) {
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

# Updating ARP stats
# Getting current stats from the database
$sql_getstats = "SELECT queries, replies, query_time, reply_time FROM arp_stats WHERE sensorid = $sensorid";
$sth_getstats = $dbh->prepare($sql_getstats);
$result_getstats = $sth_getstats->execute();
@row_getstats = $sth_getstats->fetchrow_array;
$db_queries = $row_getstats[0];
$db_replies = $row_getstats[1];
$db_query_time = $row_getstats[2];
$db_reply_time = $row_getstats[3];

# Get the threshold for this sensor
$sql_threshold = "SELECT arp_threshold_perc FROM sensors WHERE id = $sensorid";
$sth_threshold = $dbh->prepare($sql_threshold);
$result_threshold = $sth_threshold->execute();
@row_threshold = $sth_threshold->fetchrow_array;
$db_threshold = $row_threshold[0];

# Calculate new total queries and time measured
if ($type eq "query") {
  $total_count = $count + $db_queries;
  $total_time = $arp_mon_stats_period + $db_query_time;
} else {
  $total_count = $count + $db_replies;
  $total_time = $arp_mon_stats_period + $db_reply_time;
}

# Calculating total average queries per $arp_mon_stats_period minutes
$total_avg = ceil($total_count / ($total_time / $arp_mon_stats_period));
# Calculating period average queries per minute
#$period_avg = floor($count / $arp_mon_stats_period);

# Update new stats to the database
$time = time();
if ($type eq "query") {
  $sql_insert = "UPDATE arp_stats SET timestamp = $time, queries = $total_count, query_time = $total_time, avg_query = $total_avg WHERE sensorid = $sensorid";
  $threshold_query_count = ($total_avg * $db_threshold) / 100;

  open(LOG, ">> /opt/surfnetids/scripts/query.log");
  print "TOTAL_COUNT = COUNT + DB_QUERIES\n";
  print "$total_count = $count + $db_queries\n";
  print "TOTAL_TIME = ARP_MON_STATS_PERIOD + DB_QUERY_TIME\n";
  print "$total_time = $arp_mon_stats_period + $db_query_time\n";
  print "TOTAL_AVG = TOTAL_COUNT / (TOTAL_TIME / ARP_MON_STATS_PERIOD)\n";
  print "$total_avg = $total_count / $total_time * $arp_mon_stats_period\n";
  print "THRESHOLD_QUERY_COUNT = (TOTAL_AVG * ARP_QUERY_DEVIATION) / 100\n";
  print "$threshold_query_count = ($total_avg * $db_threshold) / 100\n";
  print "========================================================================\n";
  close(LOG);

  if ($count > $threshold_query_count) {
    # Threshold was exceeded
    $timestamp = time();
    $sql_log = "INSERT INTO arp_log (timestamp, sensorid, type, arp_queries, arp_time, arp_threshold, arp_query_avg) VALUES ($timestamp, $sensorid, 1, $count, $arp_mon_stats_period, $threshold_query_count, $total_avg)";
    $sth_log = $dbh->prepare($sql_log);
    $execute_result = $sth_log->execute();
  }
} else {
  $sql_insert = "UPDATE arp_stats SET timestamp = $time, replies = $total_count, reply_time = $total_time, avg_reply = $total_avg WHERE sensorid = $sensorid";
  $threshold_reply_count = ($total_avg * $db_threshold) / 100;

  if ($count > $threshold_reply_count) {
    # Threshold was exceeded
    $timestamp = time();
    $sql_log = "INSERT INTO arp_log (timestamp, sensorid, type, arp_replies, arp_time, arp_threshold, arp_reply_avg) VALUES ($timestamp, $sensorid, 2, $count, $arp_mon_stats_period, $threshold_reply_count, $total_avg)";
    $sth_log = $dbh->prepare($sql_log);
    $execute_result = $sth_log->execute();
  }
}
$sth = $dbh->prepare($sql_insert);
$execute_result = $sth->execute();
