#!/usr/bin/perl

############################################
# Route check script for IDS tunnel server #
# SURFnet IDS                              #
# Version 1.03.01                          #
# 11-10-2006                               #
# Jan van Lith & Kees Trippelvitz          #
############################################

#####################
# Changelog:
# 1.03.01 Released as part of the 1.03 package
# 1.02.01 Initial release
#####################

####################
# Modules used
####################
use DBI;
use Time::localtime;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
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
  $logfile = "$surfidsdir/log/$day$month$year/$logfile";
} else {
  $logfile = "$surfidsdir/log/$logfile";
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
  } else {
    my $ec = "Err - $?";
  }
}

####################
# Main script
####################

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $if] Starting routecheck.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
      or die $DBI::errstr;

$option = $ARGV[0];
$help = 0;
$fail = 0;

if ($option) {
  if ($option eq "--help") {
    print "Usage: ./routecheck.pl [--help | -f]\n";
    print "-f \t\t Show fails only.\n";
    print "--help \t\t Show this help.\n";
    $help = 1;
  } elsif ($option == "-f") {
    $fail = 1;
  }
}

if ($help == 0) {
  print LOG "-----Starting tunnel server check-----\n";
  print "-----Starting tunnel server check-----\n";
  $ts = getts();
  $taplist=`ifconfig | grep tap`;
  @tap_ar = split(/\n/, $taplist);

  foreach $i (@tap_ar) {
    @if = split(/ +/, $i);
    $tap = $if[0];
    $ip = `ifconfig $tap | grep "inet addr:" | cut -d":" -f2 | cut -d" " -f1 2>/dev/null`;
    chomp($ip);
    if ($ip) {
      if ($fail == 0) {
        print LOG "[$ts - $tap] IP check: \t\t\tOK\n";
        print "[$ts - $tap] IP check: \t\t\tOK\n";
      }
      $rulecheck = `ip rule list | grep "$tap" | grep "$ip" | wc -l`;
      if ($rulecheck == 0) {
        print LOG "[$ts - $tap] Rule check: \t\tFAILED\n";
        print "[$ts - $tap] Rule check: \t\tFAILED\n";
      } else {
        if ($fail == 0) {
          print LOG "[$ts - $tap] Rule check: \t\tOK\n";
          print "[$ts - $tap] Rule check: \t\tOK\n";
        }
      }
    } else {
      print LOG "[$ts - $tap] IP check: \t\t\tFAILED\n";
      print "[$ts - $tap] IP check: \t\t\tFAILED\n";
    }
    $routecheck = `ip route list table $tap | wc -l`;
    if ($routecheck == 2) {
      if ($fail == 0) {
        print LOG "[$ts - $tap] Route check: \t\tOK\n";
        print "[$ts - $tap] Route check: \t\tOK\n";
      }
    } else {
      print LOG "[$ts - $tap] Route check: \t\tFAILED\n";
      print "[$ts - $tap] Route check: \t\tFAILED\n";
    }

    $sth = $dbh->prepare("SELECT tapip FROM sensors WHERE tap = '$tap'");
    $execute_result = $sth->execute();
    if ($execute_result != 0) {
      if ($fail == 0) {
        print LOG "[$ts - $tap] DB Tap check: \t\tOK\n";
        print "[$ts - $tap] DB Tap check: \t\tOK\n";
      }
      @row = $sth->fetchrow_array;
      $tapip = @row[0];
      if ($ip != $tapip) {
        print LOG "[$ts - $tap] DB Tap IP check: \t\tFAILED\n";
        print "[$ts - $tap] DB Tap IP check: \t\tFAILED\n";
      } else {
        if ($fail == 0) {
          print LOG "[$ts - $tap] DB Tap IP check: \t\tOK\n";
          print "[$ts - $tap] DB Tap IP check: \t\tOK\n";
        }
      }
    } else {
      print LOG "[$ts - $tap] DB Tap check: \t\tFAILED\n";
      print "[$ts - $tap] DB Tap check: \t\tFAILED\n";
    }
  }
  print LOG "-----Stopping tunnel server check-----\n";
  print "-----Stopping tunnel server check-----\n";
}
$dbh = "";

# Closing log filehandle.
close(LOG);
