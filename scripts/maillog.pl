#!/usr/bin/perl
####################################
# Mail logging information         #
# SURFnet IDS          	           #
# Version 1.02.06                  #
# 19-05-2006          	           #
# Jan van Lith & Kees Trippelvitz  #
####################################

#########################################################################################
# Changelog:
# 1.02.06 Fixed a bug in the timestamp of the logfiles.
#########################################################################################

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

# This script will send a mail clearsigned with gnupgp containing information about
# the amount of attacks and all the attacks detailed with ip, time of attack and type of attack.  

####################
# Modules used
####################
use DBI;
use Time::Local;
use Time::localtime;
use Net::SMTP;
use MIME::Lite;
use GnuPG qw( :algo );

####################
# Variables used
####################
do '/etc/surfnetids/surfnetids-log.conf';
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
}
else {
  $logfile = "$surfidsdir/log/$logfile";
}

##################
# Functions
##################
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

sub getdate {
  my $stamp = $_[0];
  $tm = localtime($stamp);
  my $dd = $tm->mday;
  my $mo = $tm->mon + 1;
  my $yy = $tm->year + 1900;
  if ($dd < 10) { $dd = "0" .$dd; }
  if ($mo < 10) { $mo = "0" .$mo; }
  my $datestring = "$dd-$mo-$yy";
  return $datestring;
}

####################
# Main script
####################

# Opening log file
open(LOG, ">> $logfile");

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

# Setting time/date and timestamps
$sec = localtime->sec();
$min = localtime->min();
$hour = localtime->hour();
$day = localtime->mday();
$mon = localtime->mon() + 1;
$year = localtime->year() + 1900;

# Subtract 1 from the day for the start date/stamp.
$startday = $day - 1;

# Get start date and stamp
$startstamp = timelocal(0, 0, 0, $startday, $mon-1, $year-1900);
$startdate = getdatetime($startstamp);

# Mail date
#$nowstamp = time();
$date = getdate($startstamp);

# Get end date and stamp
$endstamp = timelocal(0, 0, 0, $day, $mon-1, $year-1900);
$enddate = getdatetime($endstamp);

# Get organisation and email of all users with maillog enabled
$email_query = $dbh->prepare("SELECT maillog, organisation, email, id FROM login WHERE maillog != 0");
$execute_result = $email_query->execute();
while (@row = $email_query->fetchrow_array) {
  $maillog = $row[0];
  $org = $row[1];
  $email = $row[2];
  $id = $row[3];
  $mailfile = "$id" . ".mail";
  
  if ($maillog == 1) {
    # Open a mail file
    open(MAIL, ">> $mailfile");
    print MAIL "Logs from $date\n";
    print MAIL "\n";
 
    # Get total of attacks and downloads and print to the mail
    $sql = "SELECT DISTINCT attacks.severity, COUNT(attacks.severity) as total FROM attacks, sensors WHERE attacks.timestamp >= '$startstamp' AND attacks.timestamp <= '$endstamp' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' GROUP BY attacks.severity";
    $overview_query = $dbh->prepare("SELECT DISTINCT attacks.severity, COUNT(attacks.severity) as total FROM attacks, sensors WHERE attacks.timestamp >= '$startstamp' AND attacks.timestamp <= '$endstamp' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' GROUP BY attacks.severity");
    $execute_result = $overview_query->execute();
    $malattacks = $overview_query->rows;
    if ($execute_result == 0 ) {
      print MAIL "No malicious attacks\n";
    }
    else {
      while (@row = $overview_query->fetchrow_array) {
        $severity = "";
        $totalsev = 0;
        $severity = $row[0];
        $totalsev = $row[1];
        if ($severity == 0 ) { print MAIL "Possible Malicious Attack\t:$totalsev\n"; } 
        elsif ($severity == 1 ) { print MAIL "Malicious Attack\t\t:$totalsev\n"; } 
        elsif ($severity == 16 ) { print MAIL "Malware offered\t\t\t:$totalsev\n"; } 
        elsif ($severity == 32 ) { print MAIL "Malware downloaded\t\t:$totalsev\n"; } 
      } 
    }
    print MAIL "\n";

    # Get details about the attacks and print them to mail.   
    # Printed in format: ip address attacker, time of attack, type of attack.   
    $message = "";
    $ipview_query = $dbh->prepare("SELECT DISTINCT attacks.source, attacks.timestamp, details.text, sensors.keyname FROM attacks, sensors, details WHERE details.attackid = attacks.id AND details.type = '1' AND attacks.severity = '1' AND attacks.timestamp >= '$startstamp' AND attacks.timestamp <= '$endstamp' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' GROUP BY source, timestamp, text, keyname ORDER BY timestamp ASC");
    $execute_result = $ipview_query->execute();
    while (@row = $ipview_query->fetchrow_array) {
      $ip = "";
      $timestamp = "";
      $attacktype = "";
      $ip = $row[0];
      $timestamp = $row[1];
      $time = getdatetime($timestamp);
      $attacktype = $row[2]; 
      $attacktype =~ s/Dialogue//; 
      $keyname = $row[3];
      $message = $message . "$keyname\t$ip\t$time\t\t$attacktype\n";
    }
    print MAIL "------ Malicious Attacks ------\n";
    print MAIL "\n";
    print MAIL "Sensor\tSource IP\tTimestamp\tAttack Type\n";
    print MAIL "$message";
    print MAIL "\n";
    close(MAIL);
    &sendmail($email, $id);
  }
  elsif ($maillog == 2) {
    # Open a mail file
    open(MAIL, ">> $mailfile");
    print MAIL "Logs from $date\n";
    print MAIL "\n";

    $sql_ranges = $dbh->prepare("SELECT DISTINCT ranges FROM organisations WHERE id = $org");
    $result_ranges = $sql_ranges->execute();
    @rangerow = $sql_ranges->fetchrow_array;
    @rangerow = split(/;/, "@rangerow");
    foreach $range (@rangerow) {
      # Get details about the attacks and print them to mail.
      # Printed in format: ip address attacker, time of attack, type of attack.
      $message = "";
      $ipview_query = $dbh->prepare("SELECT DISTINCT source, timestamp, text FROM attacks, sensors, details WHERE attacks.source <<= '$range' AND details.attackid = attacks.id AND details.type = '1' AND attacks.severity = '1' AND attacks.timestamp >= '$startstamp' AND attacks.timestamp <= '$endstamp' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' GROUP BY source, timestamp, text");
      $execute_result = $ipview_query->execute();
      if ($execute_result == 0 ) {
        print MAIL "No malicious attacks from range: $range\n";
      }
      else {
        print MAIL "$execute_result malicious attacks from range: $range\n"; 
        while (@row = $ipview_query->fetchrow_array) {
          $ip = "";
          $timestamp = "";
          $attacktype = "";
          $ip = $row[0];
          $timestamp = $row[1];
          $time = getdatetime($timestamp);
          $attacktype = $row[2];
          $attacktype =~ s/Dialogue//;
          $message = $message . "\t$ip\t$time\t$attacktype\n";
        }
        print MAIL "$message\n";
        print MAIL "\n";
      }
    }
    print MAIL "\n";
    close(MAIL);
    &sendmail($email, $id);
  }
}

sub sendmail {
  # Get variables : mailaddress to send to, Date, sender, recipient, subject and your SMTP mailhost
  $email = $_[0];
  $id = $_[1];
  $maildata = "$id" . ".mail";
  $sigmaildata = "$maildata" . ".sig";
  $from_address = $from_address;
  $to_address = "$email";
  $mail_host = 'localhost';
  $subject = "SURFnet IDS stats for $date";

  # Encrypt the mail with gnupg 
  $gpg = new GnuPG();
  $gpg->clearsign( plaintext => "$maildata", output => "$sigmaildata",
                         armor => 1, passphrase => $passphrase
                         );

  #### Create the multipart container
  $msg = MIME::Lite->new (
    From => $from_address,
    To => $to_address,
    Subject => $subject,
    Type =>'multipart/mixed'
  ) or die "Error creating multipart container: $!\n";

  ### Add the signed file
  $msg->attach (
    Type => 'text/plain; charset=ISO-8859-1',
    Path => $sigmaildata,
    Filename => $sigmaildata,
  ) or die "Error adding $sigmaildata: $!\n";

  ### Send the Message
#  MIME::Lite->send('smtp', $mail_host, Timeout=>60, Hello=>"$mail_hello", From=>"$from_address");
  MIME::Lite->send('sendmail');
  $msg->send;

  # Print info to a log file
  $localtime = time();
  $localtime = getdatetime($localtime);
  print LOG "[$localtime] Mailed stats for $date to: $email with organisation $org\n";

  # Delete the mail and signed mail  
  system "rm $maildata";
  system "rm $sigmaildata";

}

# Closing database connection.
close(LOG);

