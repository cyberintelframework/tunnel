#!/usr/bin/perl -w

###########################################
# Backup script for IDS server database   #
# SURFnet IDS                             #
# Version 1.02.03                         #
# 15-05-2006                              #
# Peter Arts                              #
###########################################

#########################################################################################
# Copyright (C) 2005-2006 SURFnet                                                       #
# Author Peter Arts                                                                     #
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

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-log.conf';
$logfile =~ s|.*/||;
if ($logstamp == 1) {
  $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  $year = localtime->year() + 1900;
  if ( ! -d "$surfidsdir/log/$day$month$year" ) {
    mkdir("$surfidsdir/log/$day$month$year");
  }
  $logfile = "$surfidsdir/log/$day$month$year/$logfile";
}
else {
  $logfile = "$surfidsdir/log/$logfile";
}

$gen_year = $ARGV[0];
$gen_month = $ARGV[1];

$count = @ARGV;
if ($count < 2) {
  # Use default values:
  $gen_month = localtime->mon();
  if ($gen_month eq 0) {
    $gen_month = 11;
    $gen_year = (localtime->year() + 1900) - 1;
  } else {
    $gen_year = (localtime->year() + 1900);
  }
}

##################
# Functions
##################

sub getts {
  my $ts = time();
  my $tsyear = localtime->year() + 1900;
  my $tsmonth = localtime->mon() + 1;
  if ($tsmonth < 10) {
    $tsmonth = "0" . $tsmonth;
  }
  my $tsday = localtime->mday();
  if ($tsday < 10) {
    $tsday = "0" . $tsday;
  }
  my $tshour = localtime->hour();
  if ($tshour < 10) {
    $tshour = "0" . $tshour;
  }
  my $tsmin = localtime->min();
  if ($tsmin < 10) {
    $tsmin = "0" . $tsmin;
  }
  my $tssec = localtime->sec();
  if ($tssec < 10) {
    $tssec = "0" . $tssec;
  }

  my $timestamp = "$tsday-$tsmonth-$tsyear $tshour:$tsmin:$tssec";
}

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");
$ts = getts();
print LOG "[$ts] Starting stat_generator.pl for year $gen_year and month $gen_month\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass);
$ts = getts();
# Check if the connection to the database did not fail.
if (! $dbh eq "") {
  print LOG "[$ts] Connecting to $pgsql_dbname with DSN: $dsn\n";
  print LOG "[$ts] Connect result: $dbh\n";
  
  # First check if this month/year isn't used for backup already
  $sql = "SELECT COUNT(*) FROM stats_history WHERE month = $gen_month AND year = $gen_year";
  $query = $dbh->prepare($sql);
  $result = $query->execute();
  @row = $query->fetchrow_array;
  $count = $row[0];
  if ($count > 0) {
    print "\n### FATAL ERROR ###\n";
    print "This month/year is already present in history table. Script abborted.\n";
    $ts = getts();
    print LOG "[$ts] This month/year is already present in history table. Script abborted.\n";
    $dbh = "";

    # Closing the logfile handle.
    $ts = getts();
    print LOG "[$ts] -------------Finished stat_generator.pl-------------\n";
    close(LOG);
    exit
  }

  # Update Dialogues:
  $sql = "SELECT DISTINCT(text) FROM details WHERE type = 1 AND text NOT IN ( SELECT name FROM stats_dialogue )";
  $query = $dbh->prepare($sql);
  $result = $query->execute();

  # Foreach Dialogue which is NOT in stats_dialogue:
  while (@insert = $query->fetchrow_array) {
    # insert:
    $sql = "INSERT INTO stats_dialogue (name) VALUES ('" . $insert[0] . "')";
    $execute_result = $dbh->do($sql);
  }  

  # Update viruses:
  $sql = "SELECT DISTINCT(info) FROM binaries WHERE info NOT IN ( SELECT name FROM stats_virus )";
  $query = $dbh->prepare($sql);
  $result = $query->execute();

  # Foreach virus which is NOT in stats_virus:
  while (@insert = $query->fetchrow_array) {
    # insert:
    $sql = "INSERT INTO stats_virus (name) VALUES ('" . $insert[0] . "')";
    $execute_result = $dbh->do($sql);
  }

  # Input: 1 = Jan, 12 = Dec.
  # Perl: 0 = Jan, 11 = Dec.
  # DB: 1 = Jan, 12 = Dec.
  $start_month = ($gen_month - 1);
  $start_year = $gen_year;
  if ($gen_month < 12) {
    # start_month + 1 == gen_month == end_month
    $end_month = $gen_month;
    $end_year = $gen_year;
  } else {
    $end_month = 0;
    $end_year = ($gen_year + 1);
  }

  # The timestamps for the start and end of the backup period.
  $startstamp = timelocal(0, 0, 0, 1, $start_month, $start_year);
  $endstamp = timelocal(0, 0, 0, 1, $end_month, $end_year);

  print LOG "[$ts] Startdate: 1-$gen_month-$gen_year\n";
  print LOG "[$ts] Enddate: $1-$end_month-$end_year\n";
  print LOG "[$ts] Startstamp in db >= $startstamp\n";
  print LOG "[$ts] Endstamp in db < $endstamp\n";

  # Get all the sensors.
  $sensor_query = $dbh->prepare("SELECT id FROM sensors");
  $ts = getts();
  $execute_result = $sensor_query->execute();
  $ts = getts();
  print LOG "[$ts] Total sensors: $execute_result\n";

  # Foreach sensor:
  while (@sensors = $sensor_query->fetchrow_array) {
    # Get the sensor ID.
    $sensorid = $sensors[0];
    $ts = getts();
    $attack_query = $dbh->prepare("SELECT COUNT( severity ) AS total FROM attacks WHERE timestamp >= $startstamp AND timestamp < $endstamp AND sensorid = $sensorid GROUP BY severity ORDER BY severity");
    print LOG "[$ts] SELECT COUNT(severity) AS total FROM attacks WHERE timestamp >= $startstamp AND timestamp < $endstamp AND sensorid = $sensorid GROUP BY severity ORDER BY severity\n";
    $ts = getts();
    $execute_result = $attack_query->execute();
    print LOG "[$ts] attack_query_result: $execute_result\n";
    $ts = getts();

    # Reset these variables to be certain they are 0.
    $possible = $malicious = $offered = $downloaded = 0;

    # Fetch the attack info.
    if ($execute_result > 0) {
      @row = $attack_query->fetchrow_array;
      $possible = $row[0];
    }
    if ($execute_result > 1) {
      @row = $attack_query->fetchrow_array;
      $malicious = $row[0];
    }
    if ($execute_result > 2) {
      @row = $attack_query->fetchrow_array;
      $offered = $row[0];
    }
    if ($execute_result > 3) {
      @row = $attack_query->fetchrow_array;
      $downloaded = $row[0];
    }
    $total = $possible + $malicious + $offered + $downloaded;

    # Only backup data for active sensors
    if ($total > 0) {
       # Get the current time as a timestamp to use in the database.
       print LOG "INSERT INTO stats_history (timestamp, sensorid, month, year, possible, malicious, offered, downloaded)\n";
       print LOG " VALUES ($timestamp, $sensorid, $gen_month, $gen_year, $possible, $malicious, $offered, $downloaded)\n";
       $timestamp = time();
       $sql = "INSERT INTO stats_history (timestamp, sensorid, month, year, count_possible, count_malicious, count_offered, count_downloaded) VALUES ($timestamp, $sensorid, $gen_month, $gen_year, $possible, $malicious, $offered, $downloaded)";
       $execute_result = $dbh->do($sql);

       $sql = "SELECT id FROM stats_history WHERE timestamp = $timestamp AND sensorid = $sensorid AND month = $gen_month AND year = $gen_year";
       $query = $dbh->prepare($sql);
       $execute_result = $query->execute();
       @row = $query->fetchrow_array;
       $historyid = $row[0];
       print LOG "Found historyid $historyid \n";

       # Get detailed info
       # Dialogues:
       $sql = "SELECT stats_dialogue.id AS stats_dialogue_id, COUNT(details.text) AS count ";
       $sql .="FROM   attacks, details, stats_dialogue ";
       $sql .="WHERE  details.attackid = attacks.id ";
       $sql .="  AND  details.text = stats_dialogue.name ";
       $sql .="  AND  attacks.timestamp >= $startstamp ";
       $sql .="  AND  attacks.timestamp < $endstamp ";
       $sql .="  AND  attacks.sensorid = $sensorid ";
       $sql .="  AND  details.type = 1 ";
       $sql .="GROUP BY details.text, stats_dialogue.id";

       $query = $dbh->prepare($sql);
       $result = $query->execute();

       # Foreach Dialogue result:
       while (@insert = $query->fetchrow_array) {
         # insert into stats_history_dialogue:
         $sql = "INSERT INTO stats_history_dialogue (historyid, dialogueid, count) VALUES ('" . $historyid . "', '" . $insert[0] . "', '" . $insert[1] . "')";
         $execute_result = $dbh->do($sql);
       }

       # Viruses:
       $sql = "SELECT stats_virus.id, COUNT(binaries.info) AS count ";
       $sql .="FROM   binaries, details, stats_virus, attacks ";
       $sql .="WHERE  details.attackid = attacks.id ";
       $sql .="  AND  attacks.timestamp >= $startstamp ";
       $sql .="  AND  attacks.timestamp < $endstamp ";
       $sql .="  AND  attacks.sensorid = $sensorid ";
       $sql .="  AND  details.type = 8 ";
       $sql .="  AND  details.text = binaries.bin ";
       $sql .="  AND  binaries.info = stats_virus.name ";
       $sql .="  AND  binaries.scanner = 'ClamAV'";
      $sql.="GROUP BY binaries.info, stats_virus.id ";

       $query = $dbh->prepare($sql);
       $result = $query->execute();

       # Foreach Virus result:
       while (@insert = $query->fetchrow_array) {
         # insert into stats_history_dialogue:
         $sql = "INSERT INTO stats_history_virus (historyid, virusid, count) VALUES ('" . $historyid . "', '" . $insert[0] . "', '" . $insert[1] . "')";
         $execute_result = $dbh->do($sql);
       }

       $ts = getts();
       # Checking the result of the insert query.
       if ($execute_result == 1) {
         print LOG "[$ts] Creating backup for sensorid $sensorid: success\n";
       }
       elsif ($execute_result == 0) {
         print LOG "[$ts] Creating backup for sensorid $sensorid: failed\n";
       }
       else {
         print LOG "[$ts] Creating backup for sensorid $sensorid: unknown result\n";
       }
     }
  }
}
else {
  $ts = getts();
  print LOG "[$ts] Error connecting to database with DSN: $dsn\n";
}
# Closing database connection.
#$dbh->disconnect;
$dbh = "";

# Closing the logfile handle.
$ts = getts();
print LOG "[$ts] -------------Finished stat_generator.pl-------------\n";
close(LOG);
