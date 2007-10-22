#!/usr/bin/perl

###################################
# ARGOS redirect script           #
# SURFnet IDS                     #
# Version 2.00.01                 #
# 14-09-2007                      #
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
# 2.00.01 version 2.00
# 1.04.03 Refined sql statements 
# 1.04.02 Added template structure + changed sql statements  
# 1.04.01 Initial release
#####################

##################
# Modules used
##################
use Time::localtime qw(localtime);
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

printlog("################ Starting to_argos.pl ################# ");

printlog("Resetting iptables Rules");
`/etc/init.d/iptables.ipvs`;

$dbconn = connectdb();

$sql = "SELECT sensors.id, sensors.tapip, argos_images.serverip, argos_templates.abbr, argos.timespan FROM argos, argos_images, argos_templates, sensors   WHERE sensors.id = argos.sensorid  AND argos.imageid = argos_images.id AND argos.templateid = argos_templates.id AND sensors.status = 1 GROUP BY sensors.tapip, sensors.vlanid, argos_images.serverip, argos_templates.abbr, sensors.id, argos.timespan ORDER BY sensors.id";
$sensor_query = $dbh->prepare($sql);
$er = $sensor_query->execute();

while (@row = $sensor_query->fetchrow_array) {
  $sensorid = $row[0];
  $tapip = $row[1];
  $serverip = $row[2];
  $template = $row[3];
  $timespan = $row[4];

  $ipfwm = `ipvsadm -L |grep -B 1 "$serverip" |head -n1 |awk '{print \$2}'`;

  
  $time_end = time();
  if ($timespan eq 'D') {
    $time_start = $time_end - (24 * 60 * 60);
  }
  if ($timespan eq 'W') {
    $time_start = $time_end - (7 * 24 * 60 * 60);
  }
  if ($timespan eq 'M') {
    $time_start = $time_end - (30 * 24 * 60 * 60);
  }
  if ($timespan eq 'Y') {
    $time_start = $time_end - (356 * 24 * 60 * 60);
  }
  if ($timespan eq 'N') {
    $time_start = '';
  }

  if ($template eq "top100sensor") {
    # BEGIN QUERY
    $sqltop100 = "SELECT attacks.source, COUNT(attacks.source) as top FROM attacks ";
    $sqltop100 .= "WHERE attacks.sensorid = $sensorid AND attacks.severity = 0 ";
    $sqltop100 .= "AND NOT attacks.source IN (SELECT source FROM attacks WHERE severity = 1) ";
    $sqltop100 .= "AND NOT attacks.source IN (SELECT source FROM attacks WHERE severity = 2) ";
    if ($timespan ne 'N') {
      $sqltop100 .= "AND attacks.timestamp >= $time_start AND attacks.timestamp <= $time_end ";
    }
    $sqltop100 .= "GROUP BY attacks.source ORDER BY top DESC LIMIT 100";
    # END QUERY

    $top100_query = $dbh->prepare($sqltop100);
    printlog("Prepared query: $sqltop100");
    $er = $top100_query->execute();

    printlog("Redirecting top100 IPs from possible malicious attacks to sensorid: $sensorid with timespan: $timespan");
    while (@rowtop100 = $top100_query->fetchrow_array) {
      $source = $rowtop100[0];
      `iptables -t mangle -A PREROUTING -s $source -d $tapip -j MARK --set-mark $ipfwm`; 
    }
  } elsif ($template eq "top100org") {
    # BEGIN QUERY
    $sqltop100 = "SELECT attacks.source, COUNT(attacks.source) as top FROM attacks ";
    $sqltop100 .= "WHERE severity = 0 ";
    $sqltop100 .= "AND sensorid IN (SELECT id FROM sensors WHERE organisation = (SELECT sensors.organisation FROM sensors WHERE id = $sensorid)) ";
    $sqltop100 .= "AND NOT attacks.source IN (SELECT source FROM attacks WHERE severity = 1) ";
    $sqltop100 .= "AND NOT attacks.source IN (SELECT source FROM attacks WHERE severity = 2) ";
    if ($timespan ne 'N') {
      $sqltop100 .= "AND attacks.timestamp >= $time_start AND attacks.timestamp <= $time_end ";
    }
    $sqltop100 .= "GROUP BY attacks.source ORDER BY top DESC LIMIT 100";
    # END QUERY

    $top100_query = $dbh->prepare($sqltop100);
    printlog ("Prepared query: $sqltop100");
    $er = $top100_query->execute();

    printlog("Redirecting top100 IPs from possible malicious attacks from the same organisation as sensorid: $sensorid with timespan: $timespan");
    while (@rowtop100 = $top100_query->fetchrow_array) {
      $source = $rowtop100[0];
      `iptables -t mangle -A PREROUTING -s $source -d $tapip -j MARK --set-mark $ipfwm`; 
    }
  } elsif ($template eq "top100all") {
    # BEGIN QUERY
    $sqltop100 = "SELECT attacks.source, COUNT(attacks.source) as top FROM attacks ";
    $sqltop100 .= "WHERE attacks.severity = 0 ";
    $sqltop100 .= "AND NOT attacks.source IN (SELECT source FROM attacks WHERE severity = 1) ";
    $sqltop100 .= "AND NOT attacks.source IN (SELECT source FROM attacks WHERE severity = 2) ";
    if ($timespan ne 'N') {
      $sqltop100 .= "AND attacks.timestamp >= $time_start AND attacks.timestamp <= $time_end ";
    }
    $sqltop100 .= "GROUP BY attacks.source ORDER BY top DESC LIMIT 100";
    # END QUERY

    $top100_query = $dbh->prepare($sqltop100);
    printlog ("Prepared query: $sqltop100");
    $er = $top100_query->execute();

    printlog("Redirecting top100 IPs from possible malicious attacks from all sensors with timespan: $timespan");
    while (@rowtop100 = $top100_query->fetchrow_array) {
      $source = $rowtop100[0];
      `iptables -t mangle -A PREROUTING -s $source -d $tapip -j MARK --set-mark $ipfwm`; 
    }
  } elsif ($template eq "all") {
    printlog("Redirecting all traffic to argos for sensorid: $sensorid");
    $source = "0/0";
    `iptables -t mangle -A PREROUTING -s $source -d $tapip -j MARK --set-mark $ipfwm`; 
  }
  
  $sql_range = "SELECT range FROM argos_ranges WHERE sensorid = $sensorid";
  $range_query = $dbh->prepare($sql_range);
  $er = $range_query->execute();

  while (@rowrange = $range_query->fetchrow_array) {
    $source = $rowrange[0];
    printlog("Redirecting range: $source to argos for sensorid: $sensorid");
    `iptables -t mangle -A PREROUTING -s $source -d $tapip -j MARK --set-mark $ipfwm`; 
  }
}
printlog("################ Finished to_argos.pl ################# ");
close(LOG);
