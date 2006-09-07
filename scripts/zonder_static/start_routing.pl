#!/usr/bin/perl

###################################
#   Routing script for IDS server #
#           SURFnet IDS           #
#           Version 1.07a         #
#            19-12-2005           #
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

# Get tap device
$if = $ARGV[0];
$sensor = $ARGV[1];

# Open log file.
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $if] Starting start_routing.pl\n";
print LOG "[$ts - $if] Sensor: $sensor\n";
# Set tablename exactly to tap device
$tablename = $if;

#print LOG "[$ts - $if] Interface: $if, Tablename: $tablename\n";

#
# MOVED to sql.pl
#
# Sleep till tunnel is fully ready and then get dhcp from remote network without setting of gateway, dns and resolv.conf 
sleep 2;
`dhclient3 -lf /var/lib/dhcp3/$if.leases -sf $surfidsdir/scripts/surfnetids-dhclient $if`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $if - $ec] Starting dhclient3: dhclient3 -sf /etc/dhcp3/dhtest-script -lf /var/lib/dhcp3/$if.leases $if\n";
sleep 1;
#
# end MOVED to sql.pl
#

# Get ip information of tap device: ip address, network, gateway 
#$ts = getts();
#$if_ip = `ifconfig $if | grep -i "inet addr:" | cut -d ":" -f2 | cut -d " " -f1`;
#chomp($if_ip);
#$ec = getec();
#print LOG "[$ts - $if - $ec] if_ip: $if_ip\n";
#$if_net = `ip route show | grep $if | awk '{print $1}'`;
#chomp($if_net);
#$ec = getec();
#print LOG "[$ts - $if - $ec] if_net: $if_net\n";
#$if_gw = `cat /var/lib/dhcp3/$if.leases | grep -A5 "$if_ip;" | grep routers | cut -d " " -f5 | head -n1`;
#chomp($if_gw);
#$if_gw = substr($if_gw, 0, -1);
#$ec = getec();
#print LOG "[$ts - $if - $ec] if_gw: $if_gw\n";

# Set routes in routing table of tap device to enable source-based routing
#`ip route add default via $if_gw table $tablename`;
#$ts = getts();
#$ec = getec();
#print LOG "[$ts - $if - $ec] Executed: ip route add default via $if_gw table $tablename\n";

# Delete all existing rules from table $if
#$total_if_ip = `ip rule list | grep -i "$if" | cut -f2 -d " " | wc -l`;
#chomp($total_if_ip);
#$ts = getts();
#print LOG "[$ts - $if] Retrieved total_if_ip: $total_if_ip\n";
#for ($i=1; $i<=$total_if_ip; $i++)
#{
#  # Get former ip address of tap device
#  $if_ip=`ip rule list | grep -i "$if" | cut -f2 -d " " | tail -1`;
#  # Delete rule from ip address in table if
#  `ip rule del from $if_ip table $if`;
#  $ts = getts();
#  pring LOG "[$ts - $if] Deleted ip rule: ip rule del from $if_ip table $if\n";
#}

# Add new rule to enable source-based routing
#$rulecheck = `ip rule list | grep $if | wc -l`;
#if ( $rulecheck == 0) {
#  `ip rule add from $if_ip table $tablename`;
#  $ts = getts();
#  $ec = getec();
#  print LOG "[$ts - $if - $ec] Added new rule: ip rule add from $if_ip table $tablename\n";
#}
#else {
#  print LOG "[$ts - $if] Rule already exists.\n";
#}

# Delete route to remote network in "main" routing table 
#`ip route del $if_net dev $if src $if_ip table main`;
#$ts = getts();
#$ec = getec();
#print LOG "[$ts - $if - $ec] Deleted route to remote network: ip route del $if_net dev $if src $if_ip table main\n";

# Add route to remote network in the tap table.
#`ip route add $if_net dev $if src $if_ip table $tablename`;
#$ts = getts();
#$ec = getec();
#print LOG "[$ts - $if - $ec] Added route to remote network: ip route add $if_net dev $if src $if_ip table $tablename\n";

print LOG "----------------finished start_routing.pl------------\n";

# Closing logfile filehandle.
close(LOG);
