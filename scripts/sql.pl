#!/usr/bin/perl

#########################################
# SURFids 2.10.00                       #
# Changeset 006                         #
# 19-08-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################
# Contributors:                         #
# Peter Arts                            #
#########################################

#####################
# Changelog:
# 006 Error check on duplicate tap's
# 005 Passing along sensorid to detectarp.pl
# 004 Added logsys stuff
# 003 Destroying statement handle before disconnecting
# 002 Don't update the tapip if statically configured
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
$prefix = "sql.pl";

# Get the tap device.
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

# Get the sensor name.
$sensor = $ARGV[1];
$remoteip = $ARGV[2];

printlog("Starting sql.pl for $sensor on $tap!");

$dbconn = connectdb();

if ("$tap" eq "") {
  logsys($prefix, 3, "NO_TAP", 0, "", $sql);
  exit 1;
} elsif ("$sensor" eq "") {
  logsys($prefix, 3, "NO_SENSOR_NAME", 0, $tap);
  exit 1;
} elsif ("$remoteip" eq "") {
  logsys($prefix, 3, "NO_REMOTEIP", 0, $tap);
  exit 1;
}

# Get the IP address configuration for the tap device from the database.
$sql = "SELECT netconf, netconfdetail, tapip, arp, id, vlanid FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
$sth = $dbh->prepare($sql);
printlog("Prepared query: $sql");
$er = $sth->execute();
printlog("Executed query: $er");

if ("$er" eq "0E0") {
  logsys($prefix, 3, "DB_FAILED_QUERY", 0, "", $sql);
}

@row = $sth->fetchrow_array;
$netconf = $row[0];
$netconfdetail = $row[1];
$tapip = $row[2];
$arp = $row[3];
$sensorid = $row[4];
$vlanid = $row[5];
$sensorname = $sensor . "-" . $vlanid;

logsys($prefix, 0, "START_SQLPL", $sensorid, $tap, "$remoteip, $netconf");

# Sleep till tunnel is fully ready 
sleep 2;

printlog("Network config method: $netconf");
$result = killdhclient($tap);  

if ($netconf eq "dhcp" || $netconf eq "vland") {
  # Start the dhcp client
  $result = startdhcp($tap);
} else { 
  # Set static network configuration without gateway, dns and resolv.conf
  # Format of netconfig: 0=>netmask|1=>gateway|2=>broadcast
  @netconfig = split(/\|/, $netconfdetail);

  $if_net = $netconfig[0];
  $if_gw = $netconfig[1];
  $if_broadcast = $netconfig[2];
  `ifconfig $tap $tapip netmask $if_net broadcast $if_broadcast`;
  if ($? != 0) {
    logsys($prefix, 3, "FAILED_STATIC_IFCONFIG", $sensorid, $tap, "$tapip, $if_net, $if_broadcast");
  } else {
    logsys($prefix, 0, "SYS_STATIC_IFCONFIG", $sensorid, $tap, "$tapip, $if_net, $if_broadcast");
  }
  $ec = getec();
  printlog("Setting IP address: $tapip - $if_net - $if_broadcast", "$ec");

  # Check for existing rules.
  $rulecheck = `ip rule list | grep $tap | wc -l`;
  chomp($rulecheck);
  if ($rulecheck == 0) {
    $result = ipruleadd($tap, $tapip);
    if ($? != 0) {
      logsys($prefix, 3, "FAILED_ADD_IPRULE", $sensorid, $tap, $tapip);
    } else {
      logsys($prefix, 0, "SYS_ADD_IPRULE", $sensorid, $tap, $tapip);
    }
  } else {
    $result = deliprules($tap);
    $result = ipruleadd($tap, $tapip);
    if ($? != 0) {
      logsys($prefix, 3, "FAILED_ADD_IPRULE", $sensorid, $tap, $tapip);
    } else {
      logsys($prefix, 0, "SYS_ADD_IPRULE", $sensorid, $tap, $tapip);
    }

    $checktap = `$c_surfidsdir/scripts/checktap.pl $tap`;
    if ($? != 0) {
      logsys($prefix, 3, "FAILED_RUN_CHECKTAP", $sensorid, $tap);
    } else {
      logsys($prefix, 0, "SYS_RUN_CHECKTAP", $sensorid, $tap, $tapip);
    }
    $ec = getec();
    printlog("Running: $c_surfidsdir/scripts/checktap.pl $tap", "$ec");
  }

  # Just to be sure, flush the routing table of the tap device.
  flushroutes($tap);
  if ($? != 0) {
    logsys($prefix, 3, "FAILED_FLUSH_ROUTES", $sensorid, $tap);
  } else {
    logsys($prefix, 0, "SYS_FLUSH_ROUTES", $sensorid, $tap);
  }
  $ec = getec();
  printlog("Flushing $tap routing table!", "$ec");

  # Calculate the network based on the tapip and the netmask.
  $network = getnetwork($tapip, $if_net);
  $ec = getec();
  printlog("Network: $network", "$ec");
  logsys($prefix, 0, "INFO_NETWORK", $sensorid, $tap, $network);

  # Check if there are any routes present in the main routing table.
  $routecheck = `ip route list | grep $tap | wc -l`;
  chomp($routecheck);
  $ec = getec();
  printlog("IP routes present in main table: $routecheck", "$ec");
  logsys($prefix, 0, "INFO_COUNT_ROUTES", $sensorid, $tap, $routecheck);

  if ($routecheck == 0) {
    # If none were present, add it. This needs to be done otherwise you'll get an error when adding the default gateway
    # for the tap device routing table.
    $result = addroute($network, $tap, $tapip, "main");
    if ($? != 0) {
      logsys($prefix, 3, "FAILED_ADD_ROUTE", $sensorid, $tap, "$network, $tapip, main");
    } else {
      logsys($prefix, 0, "SYS_ADD_ROUTE", $sensorid, $tap, "$network, $tapip, main");
    }
    $ec = getec();
    printlog("Adding route to table main", "$ec");
  }

  # Add default gateway to the routing table of the tap device.
  $result = adddefault($if_gw, $tap);
  if ($? != 0) {
    logsys($prefix, 3, "FAILED_ADD_DEFGW_TAP", $sensorid, $tap, $if_gw);
  } else {
    logsys($prefix, 0, "SYS_ADD_DEFGW_TAP", $sensorid, $tap, $if_gw);
  }
  $ec = getec();
  printlog("Adding default route to table $tap", "$ec");

  # At this point we can delete the route to the network from the main table as there is now a default gateway in
  # the routing table from the tap device.
  $result = delroute($network, $tap, $tapip, "main");
  if ($? != 0) {
    logsys($prefix, 3, "FAILED_DEL_TAPGW_MAIN", $sensorid, $tap, "$network, $tapip, main");
  } else {
    logsys($prefix, 0, "SYS_DEL_TAPGW_MAIN", $sensorid, $tap, "$network, $tapip, main");
  }
  $ec = getec();
  printlog("Deleting route from table main", "$ec");

  # Add the route to the network to the routing table of the tap device.
  $result = addroute($network, $tap, $tapip, $tap);
  if ($? != 0) {
    logsys($prefix, 3, "FAILED_ADD_ROUTE_TAP", $sensorid, $tap, "$network, $tapip");
  } else {
    logsys($prefix, 0, "SYS_ADD_ROUTE_TAP", $sensorid, $tap, "$network, $tapip");
  }
  $ec = getec();
  printlog("Adding route to table $tap", "$ec");
}

$count = 0;
$i = 0;
# Check if the tap device has an IP address.
while ($count == 0 && $i < $c_sql_dhcp_retries) {
  # First check if the tap device still exists, if not, it could not get an IP address with DHCP.
  $tapcheck = `ifconfig $tap`;
  if ($? != 0) {
    $count = 1;
    $ec = getec();

    logsys($prefix, 3, "NO_TAP_DEVICE", $sensorid, "");

    printlog("The tap device was not present!", "$ec");
    $err = 1;
    break;
  } else {
    $count = `ifconfig $tap | grep "inet addr:" | wc -l`;
    chomp($count);
  }
  $i++;
  if ($i == $c_sql_dhcp_retries) {
    logsys($prefix, 2, "FAILED_DHCP_GETIP", $sensorid, "");

    printlog("The tap device could not get an IP address!", "Err");
    $err = 1;
  }
  sleep 1;
}

if ($err == 0) {
  printlog("$tap device is up. Checking IP address.");

  # Get the IP address from the tap interface.
  $tap_ip = getifip($tap);
  if ($? != 0) {
    logsys($prefix, 3, "FAILED_CHK_IFIP", $sensorid, $tap, $tap_ip);
  } else {
    logsys($prefix, 0, "SYS_CHK_IFIP", $sensorid, $tap, $tap_ip);
  }
  $ec = getec();
  printlog("Tap IP address: $tap_ip", "$ec");

  # Connect to the database (dbh = DatabaseHandler or linkserver)
  $dbconn = connectdb();

  if ("$dbconn" ne "false") {
    # Check for duplicate tap db info
    $sql = "SELECT COUNT(tap) as total FROM sensors WHERE tap = '$tap'";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    if ("$er" eq "0E0") {
      logsys($prefix, 3, "DB_FAILED_QUERY", $sensorid, $tap, $sql);
    }
    @row = $sth->fetchrow_array;
    $total = $row[0];

    if ($total > 0) {
      logsys($prefix, 3, "DB_DUPLICATE_TAP", $sensorid, $tap, $total);
      $sql = "UPDATE sensors SET tap = '' WHERE tap = '$tap'";
      $er = $dbh->do($sql);
    }

    # Update Tap info to the database for the current $sensor.

    if ("$netconf" eq "vlans" || "$netconf" eq "static") {
      $sql = "UPDATE sensors SET tap = '$tap', status = 1 WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
    } else {
      $sql = "UPDATE sensors SET tap = '$tap', tapip = '$tap_ip', status = 1 WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
    }
    $er = $dbh->do($sql);
    printlog("Prepared query: $sql");
    printlog("Executed query: $er");

    if ("$er" eq "0E0") {
      logsys($prefix, 3, "DB_FAILED_QUERY", $sensorid, "", $sql);
    }
  } else {
    printlog("No database connection!");
  }

  if ($c_enable_pof == 1) {
    system "p0f -d -i $tap -o /dev/null";
    if ($? != 0) {
      logsys($prefix, 3, "FAILED_RUN_P0F", $sensorid, $tap);
    }
    printlog("Started p0f!");
  }

  if ($c_enable_arp == 1) {
    if ($arp == 1) {
      system("$c_surfidsdir/scripts/detectarp.pl $tap $sensorid &");
      if ($? != 0) {
        logsys($prefix, 3, "FAILED_RUN_ARPDETECT", $sensorid, $tap);
      }
      printlog("Started detectarp.pl!");
    }
  }
}

printlog("----------------finished sql.pl------------");

# Closing logfile filehandle.
close(LOG);

logsys($prefix, 0, "DONE_SQLPL", $sensorid, $tap);

if ("$dbh" ne "") {
  $sth = "";
  # Closing database connection.
  $dbh->disconnect;
}
