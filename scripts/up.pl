#!/usr/bin/perl

#########################################
# Startup script for IDS server         #
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
use Time::localtime qw(localtime);
use DBI;

##################
# Variables used
##################
# Get tap device that's coming up.
$tap = $ARGV[0];
$prefix = "up.pl";

# Get the remoteip.
$remoteip = $ENV{REMOTE_HOST};
chomp($remoteip);

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

# connect to the database
connectdb();

# Get the sensorid
$sql = "SELECT id FROM sensors WHERE remoteip = '$remoteip'";
$sth = $dbh->prepare($sql);
$sth->execute();
@row = $sth->fetchrow_array;
$sensorid = $row[0];

logsys($prefix, 0, "START_UPPL", $sensorid, $tap, $remoteip);

if ($tap eq "") {
  $err = 1;
  printlog("No tap device info!", "Err");

  logsys($prefix, 4, "NO_TAP_DEVICE", $sensorid, $tap);
}

if ($err == 0) {
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
    if ($? != 0) {
      logsys($prefix, 4, "FAILED_ADD_ROUTE", $sensorid, $tap, "$remoteip , $local_gw");
    } else {
      logsys($prefix, 0, "SYS_ADD_ROUTE", $sensorid, $tap, "$remoteip , $local_gw");
    }
    $ec = getec();
    printlog("Adding route via local gateway", "$ec");
  } else {

    logsys($prefix, 4, "NO_LOCAL_GATEWAY", $sensorid, $tap);

    printlog("Could not retrieve local gateway. Exiting with error!");
    printlog("-------------finished up.pl-----------");

    logsys($prefix, 0, "DONE_UPPL", $sensorid, $tap);

    exit 1;
  }
}
printlog("-------------finished up.pl-----------");
close(LOG);
logsys($prefix, 0, "DONE_UPPL", $sensorid, $tap);
