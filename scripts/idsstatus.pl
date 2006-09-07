#!/usr/bin/perl

#########################################
# Status check                          #
# SURFnet IDS                           #
# Version 1.02.04                       #
# 29-08-2006                            #
# Kees Trippelvitz                      #
#########################################

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

#############################################
# Changelog:
# 1.02.04 No tap devices = no database check
# 1.02.03 Added restart and kill for Nepenthes
# 1.02.02 Added checktap script
# 1.02.01 Initial release
#############################################

####################
# Modules used
####################
use DBI;
use Time::Local;
use Time::localtime;
use Net::SMTP;
use MIME::Lite;

####################
# Variables used
####################
do '/etc/surfnetids/surfnetids-tn.conf';
$statuslog = "$surfidsdir/log/idsstatus.log";
@nepenthesexec = ("/etc/init.d/nepenthes");
$err = 0;

####################
# Functions
####################
sub sendmail {
  # Get variables : mailaddress to send to, Date, sender, recipient, subject and your SMTP mailhost
  $maildata = "$statuslog";
  $from_address = 'ids@surfnet.nl';
  $to_address = 'ids@surfnet.nl';
  $mail_host = 'localhost';
  $subject = "Honey IDS error";

  #### Create the multipart container
  $msg = MIME::Lite->new (
    From => $from_address,
    To => $to_address,
    Subject => $subject,
    Type =>'multipart/mixed'
  ) or die "Error creating multipart container: $!\n";

  ### Add the file
  $msg->attach (
    Type => 'text/plain; charset=ISO-8859-1',
    Path => $maildata,
    Filename => $maildata,
  ) or die "Error adding $maildata: $!\n";

  ### Send the Message
  MIME::Lite->send('sendmail');
  $msg->send;
}

sub getdatetime {
  my $stamp = $_[0];
  $tm = localtime($stamp);
  my $ss = $tm->sec;
  my $mm = $tm->min;
  my $hh = $tm->hour;
  my $dd = $tm->mday;
  my $mo = $tm->mon + 1;
  my $yy = $tm->year + 1900;
  if ($ss < 10) { $ss = "0" .$ss; }
  if ($mm < 10) { $mm = "0" .$mm; }
  if ($hh < 10) { $hh = "0" .$hh; }
  if ($dd < 10) { $dd = "0" .$dd; }
  if ($mo < 10) { $mo = "0" .$mo; }
  my $datestring = "$dd-$mo-$yy $hh:$mm:$ss";
  return $datestring;
}

####################
# Main script
####################

$localtime = time();
$localtime = getdatetime($localtime);

# Open status mail file.
open(MAIL, "> $statuslog");

# Print timestamp.
print MAIL "Timestamp: $localtime\n";
print MAIL "---------------------\n";

$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass);

###############################
# Checking tap devices
###############################

$taplist=`ifconfig | grep tap`;
$tapcount=`ifconfig | grep tap | grep -v grep | wc -l`;
@tap_ar = split(/\n/, $taplist);
$fail = 1;

print "TAPCOUNT: $tapcount\n";
if ($tapcount > 0) {
  foreach $i (@tap_ar) {
    @if = split(/ +/, $i);
    $tap = $if[0];
    `$surfidsdir/scripts/checktap.pl $tap`;
    $ip = `ifconfig $tap | grep "inet addr:" | cut -d":" -f2 | cut -d" " -f1 2>/dev/null`;
    chomp($ip);
    if ($ip) {
      if ($fail == 0) {
        print MAIL "[$ts - $tap] IP check: \t\t\tOK\n";
        print "[$ts - $tap] IP check: \t\t\tOK\n";
      }
      $rulecheck = `ip rule list | grep "$tap" | grep "$ip" | wc -l`;
      if ($rulecheck == 0) {
        $err = 1;
        print MAIL "[$ts - $tap] Rule check: \t\tFAILED\n";
        print "[$ts - $tap] Rule check: \t\tFAILED\n";
      }
      else {
        if ($fail == 0) {
          print MAIL "[$ts - $tap] Rule check: \t\tOK\n";
          print "[$ts - $tap] Rule check: \t\tOK\n";
        }
      }
    }
    else {
      $err = 1;
      print MAIL "[$ts - $tap] IP check: \t\t\tFAILED\n";
      print "[$ts - $tap] IP check: \t\t\tFAILED\n";
    }
    $routecheck = `ip route list table $tap | wc -l`;
    if ($routecheck == 2) {
      if ($fail == 0) {
        print MAIL "[$ts - $tap] Route check: \t\tOK\n";
        print "[$ts - $tap] Route check: \t\tOK\n";
      }
    }
    else {
      $err = 1;
      print MAIL "[$ts - $tap] Route check: \t\tFAILED\n";
      print "[$ts - $tap] Route check: \t\tFAILED\n";
    }

    $sth = $dbh->prepare("SELECT tapip FROM sensors WHERE tap = '$tap'");
    $execute_result = $sth->execute();
    if ($execute_result != 0) {
      if ($fail == 0) {
        print MAIL "[$ts - $tap] DB Tap check: \t\tOK\n";
        print "[$ts - $tap] DB Tap check: \t\tOK\n";
      }
      @row = $sth->fetchrow_array;
      $tapip = $row[0];
      if ($ip ne $tapip) {
        $err = 1;
        print MAIL "[$ts - $tap] DB Tap IP check: \t\tFAILED\n";
        print "[$ts - $tap] DB Tap IP check: \t\tFAILED\n";
      }
      else {
        if ($fail == 0) {
          print MAIL "[$ts - $tap] DB Tap IP check: \t\tOK\n";
          print "[$ts - $tap] DB Tap IP check: \t\tOK\n";
        }
      }
    }
    else {
      $err = 1;
      print MAIL "[$ts - $tap] DB Tap check: \t\tFAILED\n";
      print "[$ts - $tap] DB Tap check: \t\tFAILED\n";
    }
  }
} else {
  print MAIL "No tap devices present.\n";
}

#####################
## Check other stuff
#####################

# Check if Nepenthes is running.
$nep=`ps -ef | grep "bin/nepenthes" | grep -v grep | wc -l`;

# Check if xinetd is running.
$xinetd=`ps -ef | grep xinetd | grep -v grep | wc -l`;
if ($xinetd == 0) {
  print MAIL "Xinetd: Not Running\n";
  $err = 1;
}
else {
  print MAIL "Xinetd: Running\n";
}

# Check if apache-ssl is running.
$apache=`ps -ef | grep apache-ssl | grep -v grep | wc -l`;
if ($apache == 0) {
  print MAIL "Apache-SSL: Not Running\n";
  $err = 1;
}
else {
  print MAIL "Apache-SSL: Running\n";
}

if ($nep == 0) {
  $err = 1;
  print "Nepenthes is not running.\n";
  # Nepenthes is not running.
  print MAIL "Nepenthes: Not Running\n";
  $ec = system(@nepenthesexec);
  if ($ec == 0) {
    print MAIL "Restart Nepenthes: Ok\n";
  } else {
    print MAIL "Restart Nepenthes: Failed\n";
  }
}
else {
  if ($tapcount > 0) {
    # Nepenthes is running, check if nepenthes still has a database connection.
    print MAIL "Nepenthes: Running\n";
    # Get first tap device
    $tap=`ifconfig | grep tap | head -n1 | cut -d" " -f1`;
    chomp($tap);
    `$surfidsdir/scripts/checktap.pl $tap`;
    # Get first tap interface ip address
    $tapip=`ifconfig $tap | grep -A1 tap | grep inet | head -n1 | cut -d":" -f2 | cut -d" " -f1`;
    chomp($tapip);

    # nmap to the server
    `nmap -P0 -sT -p 10000 $tapip`;
    sleep 5;

    $sql_check = "SELECT * FROM attacks WHERE dest = '$tapip' AND source = '$tapip' AND dport = 10000";
    $sth_check = $dbh->prepare($sql_check);
    $result_check = $sth_check->execute();

    if ($result_check == 0) {
      # Kill the current Nepenthes
      $neppid=`ps -ef | grep nepenthes | grep -v grep | awk '{print \$2}'`;
      chomp($neppid);
      $kill=`kill $neppid`;

      print MAIL "Nepenthes database connection: Failed\n";
      if ($? == 0) {
        print MAIL "Killing Nepenthes: Ok\n";
      } else {
        print MAIL "Killing Nepenthes: Failed\n";
      }
      $ec = system(@nepenthesexec);
      if ($ec == 0) {
        print MAIL "Restart Nepenthes: Ok\n";
      } else {
        print MAIL "Restart Nepenthes: Failed\n";
      }
      $err = 1;
    }
    else {
      print MAIL "Nepenthes database connection: Ok\n";
      $sql_del = "DELETE FROM attacks WHERE dest = '$tapip' AND source = '$tapip' AND dport = 10000";
      $sth_del = $dbh->prepare($sql_del);
      $result_del = $sth_del->execute();
    }
  }
}

close(MAIL);
if ($err == 1) {
  &sendmail();
}
