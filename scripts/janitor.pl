#!/usr/bin/perl

#########################################
# Janitor                               #
# SURFids 2.10.00                       #
# Changeset 002                         #
# 11-06-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

#####################
# Changelog:
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
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Main script
##################
# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

$verbose = 0;
$sim = 0;

if (grep $_ eq "-v", @ARGV) {
  $verbose = 1;
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

##############################
# Checking tapip (system)
##############################

printlog("Checking tapip (system)");

# Checks to see if all the tap interfaces with IP's are also in the database with the same IP.
@interfaces = `ifconfig -a | grep -A1 tap | grep "inet addr" | awk '{print \$2}' | awk -F: '{print \$2}'`;

foreach $ifip (@interfaces) {
  chomp($ifip);
  $tp = `ifconfig -a | grep -B1 "$ifip " | grep tap | awk '{print \$1}'`;
  chomp($tp);

  # Checking if $ifip and $tp have a rule
  $chk = `ip rule list | grep "$ifip " | grep "$tp " | wc -l`;
  chomp($chk);
  if ($chk == 0) {
    print "Adding missing rule for $tp - $ifip\n";
    if ($sim == 0) {
      `ip rule add from $ifip table $tp`;
    } else {
      print "Skipping: ip rule add from $ifip table $tp\n";
    }
  }

  $sql = "SELECT id, vlanid FROM sensors WHERE tapip = '$ifip'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  @row = $sth->fetchrow_array;
  $sid = $row[0];
  $vlan = $row[1];

  if ("$sid" ne "") {
    if ($verbose == 1) {
      print "Sensor" .$sid. "-" .$vlan. ": Ok\n";
    }
  } else {
    # There was no record of a sensor with the $ifip in the database
    print "No DB record for: $ifip\n";
  }
}

##############################
# Checking ip routes (system)
##############################

# Checks for left over routes
@routes = `ip route list | grep -v scope | grep -v default | awk '{print \$1}'`;

printlog("Checking ip routes (system)");

foreach $route (@routes) {
  chomp($route);

  $sql = "SELECT id, vlanid FROM sensors WHERE remoteip = '$route'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  @row = $sth->fetchrow_array;
  $sid = $row[0];
  $vlan = $row[1];

  if ("$sid" ne "") {
    if ($verbose == 1) {
      print "Sensor" .$id. "-" .$vlan. ": Ok\n";
    }
  } else {
    print "Deleting unused route: $route\n";

    # Deleting route as it's not in use.
    if ($sim == 0) {
      `ip route del $route`;
    } else {
      print "Skipping: ip route del $route\n";
    }
  }
}

##############################
# Checking ip rules (system)
##############################

# Checks for left over routes
@routes = `ip rule list | grep -v main | grep -v default | grep -v all | awk '{print \$3}'`;

printlog("Checking ip rules (system)");

foreach $rule (@rules) {
  chomp($rule);

  $sql = "SELECT id, vlanid FROM sensors WHERE tapip = '$rule'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  @row = $sth->fetchrow_array;
  $sid = $row[0];
  $vlan = $row[1];

  if ("$sid" ne "") {
    if ($verbose == 1) {
      print "Sensor" .$id. "-" .$vlan. ": Ok\n";
    }
  } else {
    print "Deleting unused rule: $rule\n";

    # Deleting route as it's not in use.
    if ($sim == 0) {
      `ip rule del $rule`;
    } else {
      print "Skipping: ip rule del $rule\n";
    }
  }
}

##############################
# Checking ip routes (database)
##############################

$sql = "SELECT id, vlanid, remoteip, tapip, tap, arp FROM sensors WHERE status = 1";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

printlog("Checking database info with system info");
while (@row = $sth->fetchrow_array) {
  $sid = $row[0];
  $vlan = $row[1];
  $rip = $row[2];
  $tapip = $row[3];
  $tp = $row[4];
  $arp = $row[5];

  if ("$rip" ne "") {
    # Checking ip routes
    $chk_rip = `ip route list | grep -v scope | grep -v default | awk '{print \$1}' | grep $rip | wc -l`;
    chomp($chk_rip);
    if ($chk_rip == 0) {
      $sensors{$sid}{1} = "0";
      print "Missing route: $rip\n";
      if ($sim == 0) {
        `ip route add $rip via $gw dev $dev`;
      } else {
        print "Skipping: ip route add $rip via $gw dev $dev\n";
      }
    } elsif ($chk_rip == 1) {
      $sensors{$sid}{1} = "1";
      if ($verbose == 1) {
        print "Sensor" .$sid. "-" .$vlan. ": Ok\n";
      }
    } else {
      $sensors{$sid}{1} = "0";
      print "Too many routes for $rip. FIXME!\n";
    }
  }

  # Checking tapip
  if ("$tp" ne "") {
    $chk_tip = `ifconfig $tp | grep 'inet addr:' | awk '{print \$2}' | awk -F: '{print \$2}'`;
    chomp($chk_tip);
    if ("$chk_tip" ne "$tapip") {
      print "Sensor" .$sid. "-" .$vlan. ": Fail\n";
    } else {
      if ($verbose == 1) {
        print "Sensor" .$sid. "-" .$vlan. ": Ok\n";
      }
    }
  }

  if ("$tapip" ne "") {
    # Checking ip rules
    if ("$tapip" ne "" && "$tp" ne "") {
      $chk_rule = `ip rule list | grep -v default | grep -v main | grep -v all | grep $tapip | grep $tp | wc -l`;
      chomp($chk_rule);
      if ($chk_rule == 0) {
        print "Missing rule: $tapip\n";
        $sensors{$sid}{3} = "0";
      } elsif ($chk_rule == 1) {
        $sensors{$sid}{3} = "1";
        if ($verbose == 1) {
          print "Sensor" .$sid. "-" .$vlan. ": Ok\n";
        }
      } else {
        $sensors{$sid}{3} = "0";

        # Removing duplicate ip rules for $tapip
        @rules = `ip rule list | grep $tapip | awk '{print \$2" "\$3" table "\$5}'`;

        $oldrule = "";
        foreach $rule (@rules) {
          chomp($rule);

          if ("$oldrule" ne "") {
            if ("$oldrule" eq "$rule") {
              # Duplicate rules, remove 1
              print "Deleting duplicate $rule\n";
              if ($sim == 0) {
                `ip rule del $rule`;
              } else {
                print "Skipping: ip rule del $rule\n";
              }
            }
          }
          $oldrule = $rule;
        }


        $chk_rule = `ip rule list | grep -v default | grep -v main | grep -v all | grep $tapip | grep $tp | wc -l`;
        chomp($chk_rule);
        if ($chk_rule == 0) {
          $sensors{$sid}{3} = "0";
        } elsif ($chk_rule == 1) {
          $sensors{$sid}{3} = "1";
        } else {
          $sensors{$sid}{3} = "0";
        }
      }

      $chktaprules = `ip rule list | grep "$tp " | wc -l`;
      chomp($chktaprules);
      if ($chktaprules > 1) {
        $systapip = `ifconfig $tp | grep "inet addr:" | awk '{print \$2}' | awk -F: '{print \$2}'`;
        chomp($systapip);

        # Removing obsolete ip rules
        if ("$tapip" eq "$systapip") {
          @rules = `ip rule list | grep "$tp " | awk '{print \$3}'`;
          foreach $rule (@rules) {
            chomp($rule);
            if ("$rule" ne "$tapip") {
              if ($sim == 0) {
                `ip rule del from $rule table $tp`;
              } else {
                print "Skipping: ip rule del from $rule table $tp\n";
              }
            }
          }
        }
      }
    }
  }

  if ("$tp" ne "") {
    # Checking tap routing tables
    $chk_taproute = `ip route list table $tp | grep default | wc -l`;
    chomp($chk_taproute);
    if ($chk_taproute == 0) {
      $sensors{$sid}{4} = "0";
      print "Missing default route for table $tp. FIXME!\n";
    } elsif ($chk_taproute == 1) {
      $sensors{$sid}{4} = "1";
      if ($verbose == 1) {
        print "Sensor" .$sid. "-" .$vlan. ": Ok\n";
      }
    } else {
      $sensors{$sid}{4} = "0";
      print "Too many routes for table $tp. FIXME!\n";
    }
  }

  if ($c_enable_arp == 1) {
    # Checking if detectarp.pl has to be started or stopped
    if ("$tp" ne "") {
      $chkarp = `ps -ef | grep -v grep | grep detectarp | grep $tp | wc -l`;
      chomp($chkarp);
      if ($chkarp == 0 && $arp == 1) {
        $chktap = `ifconfig $tp >/dev/null 2>/dev/null`;
        if ($chktap == 0) {
          if ($sim == 0) {
            system("$c_surfidsdir/scripts/detectarp.pl $tp &");
          } else {
            print "Skipping: $c_surfidsdir/scripts/detectarp.pl $tp &\n";
          }
        } else {
          print "Missing interface: $tp\n";
        }
      } elsif ($chkarp == 1 && $arp == 0) {
        $arppid = `ps -ef | grep -v grep | grep detectarp | grep $tp | awk '{print \$2}'`;
        chomp($arppid);
        if ($sim == 0) {
          `kill $arppid`;
        } else {
          print "Skipping: kill $arppid\n";
        }
      }
    }
  }

  # Checking if p0f has to be started
  if ("$tp" ne "") {
    $chkpof = `ps -ef | grep -v grep | grep p0f | grep $tp | wc -l`;
    chomp($chkpof);
    if ($chkpof == 0) {
      $chktap = `ifconfig $tp >/dev/null 2>/dev/null`;
      if ($chktap == 0) {
        if ($sim == 0) {
          system "p0f -d -i $tp -o /dev/null";
        } else {
          print "Skipping: p0f -d -i $tp -o /dev/null\n";
        }
      } else {
        print "Missing interface: $tp\n";
      }
    }
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
  }
}
