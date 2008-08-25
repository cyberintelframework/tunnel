#!/usr/bin/perl

#########################################
# Setmac script for IDS server          #
# SURFnet IDS 2.10.00                   #
# Changeset 002                         #
# 15-07-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

#####################
# Changelog:
# 002 Added logsys stuff
# 001 version 2.10.00 release
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);

##################
# Variables used
##################
$prefix = "setmac.pl";

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

if ("$er" eq "0E0") {
  logsys($prefix, 3, "DB_FAILED_QUERY", $sensorid, $tap, $sql);
}

@row = $sth->fetchrow_array;
$sensorid = $row[0];

logsys($prefix, 0, "START_SETMACPL", $sensorid, $tap, "$remoteip, $sensorport");

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

      if ("$er" eq "0E0") {
        logsys($prefix, 3, "DB_FAILED_QUERY", $sensorid, $tap, $sql);
      } else {
        logsys($prefix, 1, "DB_MAC_SAVED", $sensorid, $tap, $mac);
      }
    } else {
      # MAC address is present in the database, update the interface with the new mac.
      printlog("MAC address already known!");
      `ifconfig $tap hw ether $mac`;
      if ($? != 0) {
        logsys($prefix, 4, "FAILED_SET_MAC", $sensorid, $tap, $mac);
      } else {
        logsys($prefix, 0, "SYS_SET_MAC", $sensorid, $tap, $mac);
      }

      $ec = getec();
      printlog("MAC address of $tap set to $mac!", "$ec");
    }

    # Get the network config method.
    $sql = "SELECT netconf, tapip FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
    $sth = $dbh->prepare($sql);
    printlog("Prepared query: $sql");
    $er = $sth->execute();
    printlog("Executed query: $er");

    if ("$er" eq "0E0") {
      logsys($prefix, 2, "DB_FAILED_QUERY", $sensorid, $tap, $sql);
    }

    @row = $sth->fetchrow_array;
    $netconf = $row[0];
    $tapip = $row[1];
  }

  if ($netconf eq "dhcp") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: DHCP");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");

    logsys($prefix, 0, "SYS_RUN_SQLPL", $sensorid, $tap, "dhcp, $remoteip");
  } elsif ($netconf eq "vland") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: VLAN DHCP");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");

    logsys($prefix, 0, "SYS_RUN_SQLPL", $sensorid, $tap, "vland, $remoteip");
  } elsif ($netconf eq "static") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: static");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");

    logsys($prefix, 0, "SYS_RUN_SQLPL", $sensorid, $tap, "static, $remoteip");
  } elsif ($netconf eq "vlans") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";
    printlog("Network config method: VLAN static");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");

    logsys($prefix, 0, "SYS_RUN_SQLPL", $sensorid, $tap, "vlans, $remoteip");
  } elsif ($netconf ne "" && $tapip eq "") {
    printlog("Network config method: static");
    printlog("No tap IP address specified!");

    logsys($prefix, 3, "NO_STATIC_TAPIP", $sensorid, $tap);
  } else {
    # The script should never come here.
    # Start the sql.pl script to update all tap device information to the database.

    logsys($prefix, 4, "NO_NETCONF", "$sensorid", "$tap");
    system "$c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip &";

    printlog("Possible error. Netconf was empty. Trying DHCP!");
    printlog("Network config method: DHCP");
    printlog("Started sql script: $c_surfidsdir/scripts/sql.pl $tap $sensor $remoteip");
  }

  printlog("-------------Finished setmac.pl-------------");
  close(LOG);

  logsys($prefix, 0, "DONE_SETMACPL", $sensorid, $tap);

  exit 0;
} else {
  $ec = getec();
  logsys($prefix, 3, "NO_TAP_DEVICE", "$sensorid", "$tap");
  printlog("Tap device does not exist!", "$ec");
  printlog("-------------Finished setmac.pl-------------");
  close(LOG);

  logsys($prefix, 0, "DONE_SETMACPL", $sensorid, $tap);

  exit 1;
}
