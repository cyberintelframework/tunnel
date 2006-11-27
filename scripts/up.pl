#!/usr/bin/perl -w

###################################
# Startup script for IDS server   #
# SURFnet IDS                     #
# Version 1.04.02                 #
# 17-11-2006	                  #
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
# 1.04.02 Included tnfunctions.inc.pl and modified code structure
# 1.04.01 Released as 1.04.01
# 1.03.01 Released as part of the 1.03 package
# 1.02.01 Initial release
#####################

##################
# Modules used
##################
use Time::localtime;

##################
# Variables used
##################
# Get tap device that's coming up.
$tap = $ARGV[0];

do '/etc/surfnetids/surfnetids-tn.conf';
require "$surfidsdir/scripts/tnfunctions.inc.pl";

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
  if ( ! -d "$surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$surfidsdir/log/$day$month$year/$tap/$logfile";
} else {
  $logfile = "$surfidsdir/log/$logfile";
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

