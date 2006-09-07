#!/usr/bin/perl

###################################
# p0f script for IDS server       #
# SURFnet IDS                     #
# Version 1.02.01                 #
# 08-03-2006                      #
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

##################
# Modules used
##################
use DBI;
use Time::localtime;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
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

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts] Starting p0f.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
      or die $DBI::errstr;
$ts = getts();
print LOG "[$ts] Connected to $pgsql_dbname with DSN: $dsn\n";
print LOG "[$ts] Connect result: $dbh\n";

while ($line = <>) {

  @line_ar = split(/ +/, $line);
  $ip_and_port = $line_ar[0];
  if ($line_ar[2] ne "UNKNOWN") {
    $fingerprint = "$line_ar[2] - $line_ar[3]";
    $system = $line_ar[2];

    @ip_and_port_ar = split(/:/, $ip_and_port);
    $ip = $ip_and_port_ar[0];

    if ($ip ne "" && $fingerprint ne "") {
      # Get the mac address for the sensor from the database.
      $sth = $dbh->prepare("SELECT address FROM fingerprints WHERE address = '$ip'");
      $execute_result = $sth->execute();

      @row = $sth->fetchrow_array;
      $addr = $row[0];
      if ($addr eq "") {
        $timestamp = time();
        # IP address not yet in the database.
        $execute_result = $dbh->do("INSERT INTO fingerprints (timestamp, address, detail, system) VALUES ($timestamp, '$ip', '$fingerprint', '$system')");
      }
    }
  }
}
$dbh = "";
print LOG "-------------Finished pof.pl-------------\n";
close(LOG);
exit 0;
