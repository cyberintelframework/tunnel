#!/usr/bin/perl

###################################
# ARGOS routing script            #
# SURFnet IDS                     #
# Version 1.04.01                 #
# 24-11-2006                      #
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

#####################
# Changelog:
# 1.04.01 Initial release
#####################

##################
# Modules used
##################
use Time::localtime;
use DBI;

##################
# Variables used
##################

do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

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
  $logfile = "$c_surfidsdir/log/$day$month$year/$logfile";
} else {
  $logfile = "$c_surfidsdir/log/$logfile";
}

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");

printlog("Starting to_argos.pl");

printlog("Resetting iptables Rules");
`/etc/init.d/iptables.ipvs`;

$dbconn = connectdb();

$time_end = time();
$time_start = $time_end - (7 * 24 * 60 * 60);

$sql = "SELECT id, tapip FROM sensors WHERE status = 1";
$sensor_query = $dbh->prepare($sql);
printlog("Prepared query: $sql");
$er = $sensor_query->execute();
printlog("Executed query: $er");

while (@row = $sensor_query->fetchrow_array) {
  $sensorid = $row[0];
  $tapip = $row[1];

  # BEGIN QUERY
  $sqlid = "SELECT attacks.source, COUNT(attacks.source) as top FROM attacks ";
  $sqlid .= "WHERE attacks.sensorid = $sensorid AND NOT attacks.severity > 0 ";
  $sqlid .= "AND attacks.timestamp >= $time_start AND attacks.timestamp <= $time_end ";
  $sqlid .= "GROUP BY attacks.source ORDER BY top DESC LIMIT 20";
  # END QUERY

  $top_query = $dbh->prepare($sqlid);
  printlog("Prepared query: $sqlid");
  $er = $top_query->execute();
  printlog("Executed query: $er");

  printlog("Adding iptables rules for:");
  while (@row = $top_query->fetchrow_array) {
   $source = $row[0];
   `iptables -t mangle -A PREROUTING -s $source -d $tapip -j MARK --set-mark 2`; 
   printlog("$source");
  }
}
close(LOG);
