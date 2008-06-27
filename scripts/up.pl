#!/usr/bin/perl

###################################
# Startup script for IDS server   #
# SURFids 2.00.03                 #
# Changeset 001                   #
# 14-09-2007	                  #
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
# 001 version 2.00
#####################

##################
# Modules used
##################
use Time::localtime qw(localtime);

##################
# Variables used
##################
# Get tap device that's coming up.
$tap = $ARGV[0];

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
  if ( ! -d "$c_surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$c_surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$c_surfidsdir/log/$day$month$year/$tap/$logfile";
} else {
  $logfile = "$c_surfidsdir/log/$logfile";
}

##################
# Main script
##################

$err = 0;

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
printlog("Starting up.pl");
#print LOG "[$ts - $tap] Starting up.pl\n";

if ($tap eq "") {
  $err = 1;
  printlog("No tap device info!", "Err");
}

if ($err == 0) {
  # Get the remoteip.
  $remoteip = $ENV{REMOTE_HOST};
  chomp($remoteip);
  printlog("Retrieved remoteip: $remoteip");

  # Check for leftover source based routing rules and delete them.
  $delresult = deliprules($tap);

  # Check for leftover source based routing tables and delete if present.
  $flushresult = flushroutes($tap);
  $ec = getec();
  printlog("Flush $tap routing table", "$ec");  

  # Get local gateway.
  $local_gw = getlocalgw();
  $ec = getec();
  printlog("Retrieved local gateway: $local_gw", "$ec");
  if ($? == 0 && "$local_gw" ne "false") {
    # Add route to remote ip address via local gateway to avoid routing loops
    `route add -host $remoteip gw $local_gw`;
    $ec = getec();
    printlog("Adding route via local gateway", "$ec");
  } else {
    printlog("Could not retrieve local gateway. Exiting with error!");
    printlog("-------------finished up.pl-----------");
    exit 1;
  }
}
printlog("-------------finished up.pl-----------");
close(LOG);
