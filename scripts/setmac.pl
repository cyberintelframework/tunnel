#!/usr/bin/perl

###################################
# Setmac script for IDS server    #
# SURFids 2.04                    #
# Changeset 001                   #
# 30-05-2008                      #
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
use DBI;
use Time::localtime qw(localtime);

##################
# Variables used
##################
# Get tap device that's coming up.
$tap = $ENV{dev};

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

# Get sensor name.
$sensor = $ENV{common_name};
$remoteip = $ENV{REMOTE_HOST};
$sensorport = $ENV{untrusted_port};
chomp($sensorport);

$chk = connectdb();

# Get the IP address configuration for the tap device from the database.
$sql = "SELECT id FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

@row = $sth->fetchrow_array;
$sensorid = $row[0];

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
    if ("$mac" eq "false") {
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
      printlog("MAC address already known!");
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
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: DHCP");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf eq "vland") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: VLAN DHCP");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf eq "static") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: static");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf eq "vlans") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: VLAN static");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  } elsif ($netconf ne "" && $tapip eq "") {
    printlog("Network config method: static");
    printlog("No tap IP address specified!");
    printdblog($sensorid, 2);
  } else {
    # The script should never come here.
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Possible error. Netconf was empty. Trying DHCP!");
    printlog("Network config method: DHCP");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
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
