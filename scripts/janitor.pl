#!/usr/bin/perl -w

#########################################
# Janitor                               #
# SURFids 2.10.00                       #
# Changeset 005                         #
# 24-07-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

#####################
# Changelog:
# 005 Passing along sensorid to detectarp.pl
# 004 Fixed bug with empty $tp
# 003 Fixed bug with missing database record for server version
# 002 Complete remake
# 001 Initial release
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/jfuncs.inc.pl";

# Color codes
$n = "\033[0;39m";
$y = "\033[1;33m";
$r = "\033[1;31m";
$g = "\033[1;32m";

$prefix = "janitor.pl";

##################
# Main script
##################
# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

$verbose = 0;
$sim = 0;

if (grep $_ eq "-vv", @ARGV) {
  $verbose = 2;
}
if ($verbose == 0) {
  if (grep $_ eq "-v", @ARGV) {
    $verbose = 1;
  }
}
if (grep $_ eq "-s", @ARGV) {
  $sim = 1;
}

##############################
# Retrieving values
##############################

$gw = `ip route list | grep default | awk '{print \$3}'`;
chomp($gw);
$dev = `ip route list | grep default | awk '{print \$5}'`;
chomp($dev);

$sql = "SELECT id, vlanid, remoteip, tapip, tap, arp, netconf FROM sensors WHERE status = 1";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

##############################
# CHECKING DATABASE INFO
##############################

printlog("Checking database info with system info");
while (@row = $sth->fetchrow_array) {
  $sid = $row[0];
  $sensorid = $sid;
  $vlan = $row[1];
  $rip = $row[2];
  $tapip = $row[3];
  $tp = $row[4];
  $arp = $row[5];
  $netconf = $row[6];
  $sensor = "sensor" .$sid. "-" .$vlan;

  if ("$tp" ne "") {
    # INTERFACE
    ($chk_if, $err) = chkif($tp);
    logmsg($chk_if, $err, "Checking for interface:");

    if ($sim == 0) {
      if ($chk_if eq "false") {
        if ($netconf eq "dhcp" || $netconf eq "" || $netconf eq "vland") {
          $sql = "UPDATE sensors SET tap = '', tapip = NULL, status = 0 WHERE tap = '$tp'";
          $er = $dbh->do($sql);
          logsys($prefix, 0, "DB_CLEAR_TAP", $sensorid, $tp);
          logsys($prefix, 0, "DB_CLEAR_TAPIP", $sensorid, $tp);
          logsys($prefix, 0, "DB_UPDATE_STATUS", $sensorid, $tp, 0);
        } else {
          $sql = "UPDATE sensors SET tap = '', status = 0 WHERE tap = '$tp'";
          $er = $dbh->do($sql);
          logsys($prefix, 0, "DB_CLEAR_TAP", $sensorid, $tp);
          logsys($prefix, 0, "DB_UPDATE_STATUS", $sensorid, $tp, 0);
        }
      }
    }

    # INTERFACE IP ADDRESS
    ($chk_ifip, $err, $ifip) = getifip($tp);
    logmsg($chk_ifip, $err, "Checking for interface IP address:");

    if ($sim == 0) {
      if ($chk_ifip eq "false") {
        if ($netconf eq "dhcp" || $netconf eq "" || $netconf eq "vland") {
          $sql = "UPDATE sensors SET tap = '', tapip = NULL, status = 0 WHERE tap = '$tp'";
          $er = $dbh->do($sql);
          logsys($prefix, 0, "DB_CLEAR_TAP", $sensorid, $tp);
          logsys($prefix, 0, "DB_CLEAR_TAPIP", $sensorid, $tp);
          logsys($prefix, 0, "DB_UPDATE_STATUS", $sensorid, $tp, 0);
        } else {
          $sql = "UPDATE sensors SET tap = '', status = 0 WHERE tap = '$tp'";
          $er = $dbh->do($sql);
          logsys($prefix, 0, "DB_CLEAR_TAP", $sensorid, $tp);
          logsys($prefix, 0, "DB_UPDATE_STATUS", $sensorid, $tp, 0);
        }
      }
    }

    if ($chk_if eq "true" && $chk_ifip eq "true") {
      if ($ifip ne $tapip) {
        logmsg("false", "Database & System mismatch!", "Verifying interface IP address:");
        $sql_count = "SELECT COUNT(tap) as total FROM sensors WHERE tap = '$tp'";
        $sth_count = $dbh->prepare($sql_count);
        $er = $sth_count->execute();
        @row_count = $sth_count->fetchrow_array;
        $total = $row_count[0];
        if ($total == 1) {
          $sql = "UPDATE sensors SET tapip = '$ifip' WHERE tap = '$tp'";
          $er = $dbh->do($sql);
          logsys($prefix, 0, "DB_UPDATE_TAPIP", $sensorid, $tp, "$ifip, $tapip");
        }
      }
    }

    # RULE (IF)
    ($chk_rule_if, $err, $rule_if_count) = chkrule_by_if($tp);
    logmsg($chk_rule_if, $err, "Checking rule (check 1):");
  }
}

# RULE (IP)
($chk_rule_ip, $err, $rule_ip_count) = chkrule_by_ip($tapip);
logmsg($chk_rule_ip, $err, "Checking rule (check 2):");

if ("$tp" ne "") {
  if ($sim == 0 && $chk_if eq "true" && $chk_ifip eq "true") {
    # FIX RULE
    if ($chk_rule_if eq "false" && $chk_rule_ip eq "false") {
      ($chk, $err) = fix_rule($chk_rule_if, $chk_rule_ip, $tp, $tapip, $rule_if_count, $rule_ip_count);
      logmsg($chk, $err, "Fixing rules:");
      logsys($prefix, 0, "SYS_FIX_RULE", $sensorid, $tp);
    }
  }
}

# ROUTE (TABLE MAIN)
($chk_route_main, $err) = chkroute($rip, "main");
logmsg($chk_route_main, $err, "Checking main route (table main):");

if ($sim == 0 && $chk_if eq "true" && $chk_ifip eq "true") {
  if ($chk_route_main eq "false") {
    ($chk, $err) = addroute($rip, $gw, $dev, "main");
    logmsg($chk, $err, "Adding route to table main:");
    logsys($prefix, 0, "SYS_ADD_ROUTE", $sensorid, $tp, "main");
  }
}

  if ("$tp" ne "") {
    # ROUTE (TALBE TAP)
    ($chk, $err) = chkroute($tapip, $tp);
    logmsg($chk, $err, "Checking main route (table $tp):");

    # ROUTE (TABLE TAP - default)
    ($chk, $err) = chkroute("default", $tp);
    logmsg($chk, $err, "Checking default route (table $tp):");
  }

if ($c_enable_arp == 1) {
  # Checking if detectarp.pl has to be started or stopped
  if ("$tp" ne "") {
    $chkarp = `ps -ef | grep detectarp | grep -v grep | grep $tp | wc -l`;
    chomp($chkarp);
    if ($chkarp == 0 && $arp == 1) {
      $chktap = `ifconfig $tp >/dev/null 2>/dev/null`;
      if ($chk_if eq "true") {
        if ($sim == 0) {
          system("$c_surfidsdir/scripts/detectarp.pl $tp $sid &");
          logsys($prefix, 0, "SYS_START_DETECTARP", $sensorid, $tp);
        } else {
          print "Skipping: $c_surfidsdir/scripts/detectarp.pl $tp $sid &\n";
        }
      }
    } elsif ($chkarp == 1 && $arp == 0) {
      $arppid = `ps -ef | grep detectarp | grep -v grep | grep "detectarp.pl $tp " | awk '{print \$2}'`;
      chomp($arppid);
      if ("$arppid" ne "") {
        if ($sim == 0) {
          `kill $arppid`;
          logsys($prefix, 0, "SYS_KILL_DETECTARP", $sensorid, $tp);
        } else {
          print "Skipping: kill $arppid\n";
        }
      }
    }
  }
}

##############################
# CHECKING RULES
##############################

printlog("Checking rules");
$sensor = "rules ";

($chk_rules, $err, @rules) = getallrules();

foreach $rule (@rules) {
  chomp($rule);

  $sql = "SELECT id, vlanid FROM sensors WHERE tapip = '$rule' AND status = 1";
  $sth = $dbh->prepare($sql);
  $sth->execute();

  @row = $sth->fetchrow_array;
  $count = scalar(@row);
  $sensorid = $row[0];

  if ($count == 0) {
    logmsg("false", "No DB record for $rule", "Checking database for $rule:");
    if ($sim == 0) {
      ($chk, $err) = delrule_by_ip($rule);
      logmsg($chk, $err, "Deleting unused rule for $rule:");
      logsys($prefix, 0, "SYS_DEL_RULE", $sensorid, $tp, $rule);
    } else {
      logmsg("skip", "", "Delrule_by_ip($rule)");
    }
  } else {
    logmsg("true", "Database record found for $rule!", "Checking database for $rule:");
  }
}

##############################
# CHECKING ROUTES
##############################

#print "\n";
printlog("Checking routes");
$sensor = "routes";

($chk_rules, $err, @routes) = getallroutes();

foreach $route (@routes) {
  chomp($route);

  $sql = "SELECT id, vlanid FROM sensors WHERE remoteip = '$route' AND status = 1";
  $sth = $dbh->prepare($sql);
  $sth->execute();

  @row = $sth->fetchrow_array;
  $count = scalar(@row);
  $sensorid = $row[0];

  if ($count == 0) {
    logmsg("false", "No DB record for $route", "Checking database for $route:");
    if ($sim == 0) {
      ($chk, $err) = delroute($route, "main");
      logmsg($chk, $err, "Deleting unused route for $route:");
      logsys($prefix, 0, "SYS_DEL_ROUTE", $sensorid, $tp, "main");
    } else {
      logmsg("skip", "", "delroute for $route in main");
    }
  } else {
    logmsg("true", "Database record found for $route!", "Checking database for $route:");
  }
}















# Cleaning up sensor logs
$ts = time();
$ts = $ts - (60 * 60 * 24 * 7);
$sql = "DELETE FROM sensors_log USING logmessages WHERE sensors_log.timestamp < $ts AND sensors_log.logid = logmessages.id AND logmessages.type < 30";
$ec = $dbh->do($sql);

# Updating server repository version number of the sensor scripts
if (-r "$c_surfidsdir/svnroot/updates/db/current") {
  $server_rev = `cat $c_surfidsdir/svnroot/updates/db/current | awk '{print \$1}'`;
  chomp($server_rev);

  $sql_getrev = "SELECT value FROM serverinfo WHERE name = 'updaterev'";
  $sth_getrev = $dbh->prepare($sql_getrev);
  $sth_getrev->execute();

  @row = $sth_getrev->fetchrow_array;
  $server_rev_db = $row[0];
  if ("$server_rev_db" ne "") {
    if ("$server_rev_db" ne "$server_rev") {
      $ts = time();
      $sql = "UPDATE serverinfo SET value = '$server_rev', timestamp = '$ts' WHERE name = 'updaterev'";
      $ec = $dbh->do($sql);
    }
  } else {
    $sql = "INSERT INTO serverinfo (value, timestamp, name) VALUES ('$server_rev', '$ts', 'updaterev')";
    $ec = $dbh->do($sql);
  }
}
