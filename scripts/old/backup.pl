#!/usr/bin/perl -w

###########################################
# Backup script for IDS server database   #
# SURFnet IDS                             #
# BETA                                    #
# Version 1.02.01                         #
# 21-02-2006                              #
# Jan van Lith & Kees Trippelvitz         #
###########################################

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

######################
# Dialogue variables
######################
$SMBDialogue = 0;
$BagleDialogue = 0;
$DWDialogue = 0;
$DCOMDialogue = 0;
$IISDialogue = 0;
$Kuang2Dialogue = 0;
$LSASSDialogue = 0;
$MSMQDialogue = 0;
$MSSQLDialogue = 0;
$MydoomDialogue = 0;
$NETDDEDialogue = 0;
$OPTIXBindDialogue = 0;
$OPTIXShellDialogue = 0;
$OPTIXDownloadDialogue = 0;
$PNPDialogue = 0;
$SasserFTPDDialogue = 0;
$SUB7Dialogue = 0;
$SSHDialogue = 0;
$UPNPDialogue = 0;
$VERITASDialogue = 0;
$WINSDialogue = 0;

$virus_string = "";

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

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass);
$ts = getts();
# Check if the connection to the database did not fail.
if (! $dbh eq "") {
  print LOG "[$ts] Connecting to $pgsql_dbname with DSN: $dsn\n";
  print LOG "[$ts] Connect result: $dbh\n";

  # Setting some date variables.
  $startmonth = localtime->mon() - $backup_period;
  $endmonth = localtime->mon() - $backup_period;
  $isdst = localtime->isdst();
  $startday = 1;

  # Checking staryear.
  if ($startmonth < 0) {
    $startyear = localtime->year() - 1 + 1900;
  }
  else {
    $startyear = localtime->year() + 1900;
  }

  # Checking endyear.
  if ($endmonth < 0) {
    $endyear = localtime->year() - 1 + 1900;
  }
  else {
    $endyear = localtime->year() + 1900;
  }

  # Converting months to positive numbers.
  $startmonth = ($startmonth + 12) % 12;
  $endmonth = ($endmonth + 12) % 12;

  # Checking amount of days in the end month.
  if ($endmonth == 0 || $endmonth == 2 || $endmonth == 4 || $endmonth == 6 || $endmonth == 7 || $endmonth == 9 || $endmonth == 11) {
    $endday = 31;
  }
  elsif ($endmonth == 1) {
    if ($isdst == 1) {
      $endday = 29;
    }
    else {
      $endday = 28;
    }
  }
  else {
    $endday = 30;
  }

  # The timestamps for the start and end of the backup period.
  $startstamp = timelocal(0, 0, 0, $startday, $startmonth, $startyear);
  $endstamp = timelocal(59, 59, 23, $endday, $endmonth, $endyear);

  print LOG "[$ts] Startdate: $startday-$startmonth-$startyear\n";
  print LOG "[$ts] Enddate: $endday-$endmonth-$endyear\n";
  print LOG "[$ts] Startstamp: $startstamp\n";
  print LOG "[$ts] Endstamp: $endstamp\n";

  # The database should have the correct month (perlmonth + 1).
  $dbmonth = $endmonth + 1;

  # Get all the sensors.
  $sensor_query = $dbh->prepare("SELECT id FROM sensors");
  $ts = getts();
  $execute_result = $sensor_query->execute();
  $ts = getts();
  print LOG "[$ts] Total sensors: $execute_result\n";

  while (@sensors = $sensor_query->fetchrow_array) {
    # Reset the virus_string to be certain.
    $virus_string = "";
    # Get the sensor ID.
    $sensorid = $sensors[0];
    $ts = getts();
    $attack_query = $dbh->prepare("SELECT COUNT( severity ) AS total FROM attacks WHERE timestamp >= $startstamp AND timestamp <= $endstamp AND sensorid = $sensorid GROUP BY severity");
#    print LOG "[$ts] SELECT COUNT(severity) AS total FROM attacks WHERE timestamp >= $startstamp AND timestamp <= $endstamp AND sensorid = $sensorid GROUP BY severity\n";
    $ts = getts();
    $execute_result = $attack_query->execute();
    print LOG "[$ts] attack_query_result: $execute_result\n";
    $ts = getts();

    # Reset these variables to be certain they are 0.
    $possible = 0;
    $malicious = 0;
    $offered = 0;
    $downloaded = 0;

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

#    print LOG "SELECT details.text, count(*) as total FROM details, attacks WHERE details.text LIKE '%Dialogue' AND attacks.timestamp >= $startstamp AND attacks.timestamp <= $endstamp AND attacks.id = details.attackid AND attacks.sensorid = $sensorid GROUP BY details.text\n";
    # Query the database for the different attacks.
    $detail_query = $dbh->prepare("SELECT details.text, count(*) as total FROM details, attacks WHERE details.text LIKE '%Dialogue' AND attacks.timestamp >= $startstamp AND attacks.timestamp <= $endstamp AND attacks.id = details.attackid AND attacks.sensorid = $sensorid GROUP BY details.text");
    $execute_result = $detail_query->execute();

    while (@row = $detail_query->fetchrow_array) {
      $dia = $row[0];
      $count = $row[1];
      ${$dia} = $count;
    }

    print LOG "SELECT details.text FROM details, attacks WHERE details.type = 8 AND attacks.timestamp >= $startstamp AND attacks.timestamp <= $endstamp AND attacks.id = details.attackid AND attacks.sensorid = $sensorid GROUP BY details.text\n";
    # Query the database for the different hashes that are downloaded.
    $virus_query = $dbh->prepare("SELECT details.text FROM details, attacks WHERE details.type = 8 AND attacks.timestamp >= $startstamp AND attacks.timestamp <= $endstamp AND attacks.id = details.attackid AND attacks.sensorid = $sensorid GROUP BY details.text");
    $execute_result = $virus_query->execute();

    print LOG "[$ts] Offered malware for $sensorid: $execute_result\n";

    # Loop through the hashes from the query.
    while (@row = $virus_query->fetchrow_array) {
      # Lookup the virus info file.
      $virus_loc = $full_vir_dir . $row[0] . $vir_suffix;
      if (-e $virus_loc) {
        # If the virus info file exists. Check it's contents and parse the virus name out of it.
        $virus_line = `cat $virus_loc`;
        chomp($virus_line);
        @virus_line_ar = split(/ +/, $virus_line);
      
        $virus = $virus_line_ar[1];
        if (!$virus eq "") {
          # Get the count of the virus, if it exists.
          if (exists($virus_count_ar{$virus})) {
            $newcount = $virus_count_ar{$virus} + 1;
          }
          else {
            $newcount = 1;
          }
          # Set the new count in the array.
          $virus_count_ar{$virus} = $newcount;
        }
      }
    }

    # Put the virus->count in an associative array and sort it on count.
    foreach $key (sort { $virus_count_ar{$b} <=> $virus_count_ar{$a} } keys %virus_count_ar) {
      $virus_string = "$virus_string$key*$virus_count_ar{$key};";
    }

    # Get the current time as a timestamp to use in the database.
    $timestamp = time();
    $sql = "INSERT INTO history (timestamp, sensorid, month, year, possible, malicious, offered, downloaded, asn1, bagle, dameware, dcom, iis, kuang2, lsass, msmq, mssql, mydoom, netdde, optixbind, optixshell, optixdown, pnp, sasser, ssh, sub7, upnp, veritas, wins, virusinfo) VALUES ($timestamp, $sensorid, $dbmonth, $endyear, $possible, $malicious, $offered, $downloaded, $SMBDialogue, $BagleDialogue, $DWDialogue, $DCOMDialogue, $IISDialogue, $Kuang2Dialogue, $LSASSDialogue, $MSMQDialogue, $MSSQLDialogue, $MydoomDialogue, $NETDDEDialogue, $OPTIXBindDialogue, $OPTIXShellDialogue, $OPTIXDownloadDialogue, $PNPDialogue, $SasserFTPDDialogue, $SSHDialogue, $SUB7Dialogue, $UPNPDialogue, $VERITASDialogue, $WINSDialogue, '$virus_string')";
    $execute_result = $dbh->do($sql);
    $ts = getts();

    # Resetting variables all the variables again to make sure they aren't used for the next sensor.
    $virus_string = "";
    %virus_count_ar = ();
    $possible = 0;
    $malicious = 0;
    $offered = 0;
    $downloaded = 0;
    $SMBDialogue = 0;
    $BagleDialogue = 0;
    $DWDialogue = 0;
    $DCOMDialogue = 0;
    $IISDialogue = 0;
    $Kuang2Dialogue = 0;
    $LSASSDialogue = 0;
    $MSMQDialogue = 0;
    $MSSQLDialogue = 0;
    $MydoomDialogue = 0;
    $NETDDEDialogue = 0;
    $OPTIXBindDialogue = 0;
    $OPTIXShellDialogue = 0;
    $OPTIXDownloadDialogue = 0;
    $PNPDialogue = 0;
    $SasserFTPDDialogue = 0;
    $SUB7Dialogue = 0;
    $SSHDialogue = 0;
    $UPNPDialogue = 0;
    $VERITASDialogue = 0;
    $WINSDialogue = 0;
  
    # Checking the result of the insert query.
    if ($execute_result == 1) {
      print LOG "[$ts] Creating backup for sensorid $sensorid: success\n";
    }
    elsif ($execute_result == 0) {
      print LOG "[$ts] Creating backup for sensorid $sensorid: failed\n";
    }
    else {
      print LOG "[$ts] Creating backup for sensorid $sensorid: unkown result\n";
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
print LOG "[$ts] -------------Finished backup.pl-------------\n";
close(LOG);
