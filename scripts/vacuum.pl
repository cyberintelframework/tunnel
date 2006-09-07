#!/usr/bin/perl -w

###################################
# Stop script for IDS server      #
# SURFnet IDS                     #
# Version 1.02.01                 #
# 21-02-2006                      #
# Jan van Lith & Kees Trippelvitz #
###################################

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

####################
# Modules used
####################
use DBI;
use Time::localtime;

####################
# Variables used
####################
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

##################
# Functions
##################

sub getts {
  my $ts = time();
  my $year = localtime->year() + 1900;
  my $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  my $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  my $hour = localtime->hour();
  if ($hour < 10) {
    $hour = "0" . $hour;
  }
  my $min = localtime->min();
  if ($min < 10) {
    $min = "0" . $min;
  }
  my $sec = localtime->sec();
  if ($sec < 10) {
    $sec = "0" . $sec;
  }

  my $timestamp = "$day-$month-$year $hour:$min:$sec";
}

sub getec {
  if ($? == 0) {
    my $ec = "Ok";
  }
  else {
    my $ec = "Err - $?";
  }
}

####################
# Main script
####################

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts] Starting vacuum.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass);
$ts = getts();
print LOG "[$ts] Connecting to $pgsql_dbname with DSN: $dsn\n";
if ($dbh ne "") {
  print LOG "[$ts] Connect result: Ok\n";
}
else {
  print LOG "[$ts - Err] Connect result: failed\n";
  $pgerr = $DBI::errstr;
  chomp($pgerr);
  print LOG "[$ts - Err] Error message: $pgerr\n";
}

$sth = $dbh->prepare("VACUUM FULL ANALYZE sensors");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE attacks");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE details");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE binaries");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE system");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE binaries_detail");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE stats_virus");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE stats_dialogue");
$execute_result = $sth->execute();

$sth = $dbh->prepare("VACUUM FULL ANALYZE organisations");
$execute_result = $sth->execute();

# Closing database connection.
$dbh = "";

# Closing log filehandle.
close(LOG);

