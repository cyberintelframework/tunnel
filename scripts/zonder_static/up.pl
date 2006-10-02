#!/usr/bin/perl

###################################
#   Startup script for IDS server #
#	    SURFnet IDS		  #
#	    Version 1.05	  #
#	     19-12-2005		  #
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
use Time::localtime;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
$logfile =~ s|.*/||;
$logfile = "$surfidsdir/log/$logfile";
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
  $logfile = "$logfile-$day$month$year";
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

# Get tap device that's coming up.
$tap = $ARGV[0];
$sensor = $ENV{common_name};

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $tap] Starting up.pl\n";

# Get the remoteip.
$remoteip = $ENV{REMOTE_HOST};
chomp($remoteip);
$ts = getts();
print LOG "[$ts - $tap] Retrieved remoteip: $remoteip\n";

# Get local gateway.
$local_gw = `route -n | grep -i "0.0.0.0" |grep -i UG | cut -d " " -f10`;
chomp($local_gw);
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Retrieved local gateway: $local_gw\n";

# Check for leftover source based routing rules and delete them.
$total_if_ip = `ip rule list | grep -i "$tap" | cut -f2 -d " " | wc -l`;
chomp($total_if_ip);
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Retrieved routing rules: $total_if_ip\n";
for ($i=1; $i<=$total_if_ip; $i++) {
  # Get former ip address of tap device
  $if_ip = `ip rule list | grep -i "$tap" | cut -f2 -d " " | tail -1`;
  chomp($if_ip);
  # Delete rule from ip address in table if
  `ip rule del from $if_ip table $tap`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Deleted ip routing rule: ip rule del from $if_ip table $tap\n";
}

# Check for leftover source based routing tables and delete if present.
`ip route flush table $tap`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Flush $tap routing table: ip route flush table $tap\n";

# Add route to remote ip address via local gateway to avoid routing loops
`route add -host $remoteip gw $local_gw`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Added new route: route add -host $remoteip gw $local_gw\n";

# Start routing script asynchronous because of pump who wont get an ip address when tunnel isn't completely up
# start_routing sets source based routing
$ts = getts();
system "$surfidsdir/scripts/start_routing.pl $tap &";
print LOG "[$ts - $tap] Started routing script: $surfidsdir/start_routing.pl $tap $sensor &\n";

$ts = getts();
print LOG "-------------Finished up.pl-------------\n";
close(LOG);
