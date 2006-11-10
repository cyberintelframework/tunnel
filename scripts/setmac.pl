#!/usr/bin/perl -w

###################################
# Setmac script for IDS server    #
# SURFnet IDS                     #
# Version 1.04.01                 #
# 07-11-2006                      #
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
# 1.04.01 Code layout
# 1.02.03 Added vlan support 
# 1.02.02 Fixed a bug with the netconf query
# 1.02.01 Initial release
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime;

##################
# Variables used
##################
# Get tap device that's coming up.
$tap = $ENV{dev};

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

# Get sensor name.
$sensor = $ENV{common_name};
$remoteip = $ENV{REMOTE_HOST};
$sensorport = $ENV{untrusted_port};
chomp($sensorport);

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $tap] Starting setmac.pl\n";
print LOG "[$ts - $tap] Sensor: $sensor\n";

# Check for tap existance.
`ifconfig $tap`;

if ($? == 0) {
  # Tap exists, continue.
  $ec = getec();
  printlog("Tap device exists!");

  $dbconn = connectdb();
  if ($dbconn eq "true") {
    $mac = dbmacaddr("$sensor", "$remoteip");
    if ($mac ne "false") {
      # If no mac address is present in the database, add the generated one from OpenVPN to the database.
      printlog("No MAC address in sensors table for $sensor!");
      $mac = `ifconfig $tap | grep HWaddr | awk '{print \$5}'`;
      chomp($mac);
      $ec = getec();
      printlog("New MAC address: $mac", "$ec");
      $sql = "UPDATE sensors SET mac = '$mac' WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
      $er = $dbh->do($sql);
      $ts = getts();
      printlog("Prepared query: $sql");
      printlog("Executed query: $er");
    } else {
      # MAC address is present in the database, update the interface with the new mac.
      printlog("New MAC address already known!");
      `ifconfig $tap hw ether $mac`;
      $ec = getec();
      printlog("MAC address of $tap set to $mac!", "$ec");
    }

    # Get the network config method.
    $sql = "SELECT netconf, tapip FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
    $sth = $dbh->prepare($sql);
    printlog("Prepared query: $sql");
    $er = $sth->execute();
    printlog("Executed query: $er");

    @row = $sth->fetchrow_array;
    $netconf = $row[0];
    $tapip = $row[1];
  }

  if ($netconf eq "dhcp") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: DHCP");
    printlog("Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf eq "vland") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: VLAN DHCP");
    printlog("Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf eq "static") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: static");
    printlog("Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf eq "vlans") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: VLAN static");
    printlog("Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf ne "" && $tapip eq "") {
    printlog("Network config method: static");
    printlog("No tap IP address specified!");
  } else {
    # The script should never come here.
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Possible error. Netconf was empty. Trying DHCP!");
    printlog("Network config method: DHCP");
    printlog("Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  }

  printlog("-------------Finished setmac.pl-------------");
  close(LOG);
  exit 0;
} else {
  $ec = getec();
  printlog("Tap device does not exist!", "$ec");
  printlog("-------------Finished setmac.pl-------------");
  close(LOG);
  exit 1;
}
