#!/usr/bin/perl
####################################
# Mail reporter                    #
# SURFnet IDS          	           #
# Version 1.02.09                  #
# 27-06-2006          	           #
# Jan van Lith & Kees Trippelvitz  #
# Modified by Peter Arts           #
####################################

#########################################################################################
# Changelog:                                                                            
# 1.02.09 Bugfixes
# 1.02.08 Bugfix
# 1.02.07 Fully addapted for new mail reporting.                                        
# 1.02.06 Fixed a bug in the timestamp of the logfiles.                                 
#########################################################################################

#########################################################################################
# Copyright (C) 2005-2006 SURFnet                                                       #
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

# This script will send a mail clearsigned with gnupgp (if configured in webinterface) containing information
# about the amount of attacks and all the attacks detailed with ip, time of attack and type of attack.  

####################
# Modules used
####################
use DBI;
use Time::Local;
use Time::localtime;
use Net::SMTP;
use MIME::Lite;
use GnuPG qw( :algo );
use POSIX qw(floor);

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

sub gettime {
	# Without seconds
	my $stamp = $_[0];
	$tm = localtime($stamp);
	my $mm = $tm->min;
	my $hh = $tm->hour;
	if ($mm < 10) { $mm = "0" .$mm; }
	if ($hh < 10) { $hh = "0" .$hh; }
	my $datestring = "$hh:$mm";
	return $datestring;
}

####################
# Main script
####################

# Opening log file
open(LOG, ">> $logfile");

# Set now on top of this script
$ts_now = time;

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

# ts_ means timestamp
# dt_ means formatted datetime
# d_ means formatted date
# $ts_yesterday = (time - (24 * 60 * 60));
# $dt_yesterday = getdatetime($ts_yesterday);
# $d_yesterday = getdate($ts_yesterday);

# Declare timespans
$minute = 60;
$hour = (60 * $minute);
$day = (24 * $hour);
$week = (7 * $day);

# Get organisation and email of all users with mailreporting enabled and status active
$email_query = $dbh->prepare("SELECT report.email, login.organisation, report_content.id, report_content.template, report_content.sensor_id, report_content.frequency, report_content.last_sent, report_content.interval, report_content.priority, report.subject, report.gpg_enabled, report_content.title FROM report, login, report_content WHERE report.user_id = login.id AND report.enabled = TRUE AND report.id = report_content.report_id AND report_content.active = TRUE");
$execute_result = $email_query->execute();
while (@row = $email_query->fetchrow_array) {
	$email = $row[0];
	$org = $row[1];
	$id = $row[2];
	$template = $row[3];
	$sensor = $row[4];
	$frequency = $row[5];
	$last_sent = $row[6];
	$interval = $row[7];
	$priority = $row[8];
	$subject = $row[9];
	$gpg_enabled = $row[10];
	$title = $row[11];
	
	if ($last_sent eq '') {
		# Never sent before, take time it should be send and set last_sent 1 interval ago
		# Frequency day: 0 = 0:00 Hour, 1 = 1:00, 14 = 14:00, etc.
		# Frequency week: 1 = monday, 6 = saturday, 0 = sunday
		if ($frequency == 1) {
			# Every Hour
			# Has to send now, just set it 1 hour ago (so it will be send now)
			$last_sent = ($ts_now - $hour);
		} else {
			# Every day or every week
			# Save last_sent in database and set it
			# Last sent: yesterday at [interval] (every day)
			# Last sent: last week at [interval] (every week)
			$lt = localtime(time);
			if ($frequency == 2) {
				# Generate timestamp with todays date and interval time (every day)
				$ts_today = timelocal(0, 0, $interval, $lt->mday, $lt->mon, $lt->year);
				# Substract one day
				$last_sent = ($ts_today - $day);
			} elsif ($frequency == 3) {
				# If interval eq daynumber => send, else do nothing and wait for first send day
				if ($interval == $lt->wday) {
					# Generate timestamp with todays date and time = 1:00 (reports will be send at 1H) (every week)
					$ts_today = timelocal(0, 0, 1, $lt->mday, $lt->mon, $lt->year);
					# Substract one week
					$last_sent = ($ts_today - $week);
				} else { $last_sent = ''; }
			}
		}
	}

	if ($last_sent ne '') {
		# Check if a report has to be send
		# Frequency: 1 = every hour, 2 = every day, 3 = every week
		if ($frequency == 1) { $timespan = $hour; }
		elsif ($frequency == 2) { $timespan = $day; }
		elsif ($frequency == 3) { $timespan = $week; }

		$next_send = ($last_sent + $timespan);
		# Add 50 minutes to ts_now to avoid sending once in two sequences instead of every sequence
		$ts_check = ($ts_now + (50 * $minute));
		
		if ($next_send <= ($ts_now )) {
			# A report has to be send
			$send = 1;
			
			# Set start and end timestamps
			$ts_start = $last_sent;
			$ts_end = ($last_sent + $timespan);

			if ($sensor > -1) { $sensor_where = " AND sensors.id = '$sensor'"; }
			else { $sensor_where = ""; }
			$mailfile = "/tmp/" .$id. ".mail";
			
			# Open a mail file
			open(MAIL, ">> $mailfile");
			
			# Date/time when report was generated
			print MAIL "Mailreport generated at " . getdatetime(time) . "\n";
			
			# Handle templates
			# 1 = All attacks, 2 = Own ranges, 3 = Threshold

			# ALL ATTACKS:
			if ($template == 1) {
				
				print MAIL "Results from " . getdatetime($ts_start) . " till " . getdatetime($ts_end) . "\n";
				print MAIL "\n";
				
				# Get total of attacks and downloads and print to the mail
				$sql = "SELECT DISTINCT severity.txt, severity.val, COUNT(attacks.severity) as total FROM attacks, sensors, severity WHERE attacks.severity = severity.val AND attacks.timestamp >= '$ts_start' AND attacks.timestamp <= '$ts_end' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' $sensor_where GROUP BY severity.txt, severity.val ORDER BY severity.val";
				$overview_query = $dbh->prepare($sql);
				$execute_result = $overview_query->execute();
				$malattacks = $overview_query->rows;
				if ($execute_result == 0 ) {
					print MAIL "No malicious attacks detected for last timespan.\n";
				} else {
					while (@row = $overview_query->fetchrow_array) {
						$severity = $row[0];
						$value = $row[1];
						$totalsev = $row[2];
						# By default use 2 tabs
						$tab = "\t\t\t";
						if ($value == 0 ) { $tab = "\t\t"; }
					        elsif ($value == 16 ) { $tab = "\t\t\t"; } 
						print MAIL "$severity:" . $tab . $totalsev . "\n";
					} 
					print MAIL "\n";
				
					# Get details about the attacks and print them to mail.   
					# Printed in format: ip address attacker, time of attack, type of attack.   
					$message = "";
					$ipview_query = $dbh->prepare("SELECT DISTINCT attacks.source, attacks.timestamp, details.text, sensors.keyname FROM attacks, sensors, details WHERE details.attackid = attacks.id AND details.type = '1' AND attacks.severity = '1' AND attacks.timestamp >= '$ts_start' AND attacks.timestamp <= '$ts_end' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' $sensor_where GROUP BY source, timestamp, text, keyname ORDER BY timestamp ASC");
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
						$keyname = $row[3] . " ";
						$message = $message . "$keyname\t$ip\t\t$time\t$attacktype\n";
					}
					print MAIL "------ Malicious Attacks ------\n";
					print MAIL "\n";
					print MAIL "Sensor\t\tSource IP\t\tTimestamp\t\tAttack Type\n";
					print MAIL "$message";
				}
			}
			# OWN RANGES:
			elsif ($template == 2) {	
				
				print MAIL "Results from " . getdatetime($ts_start) . " till " . getdatetime($ts_end) . "\n";
				print MAIL "\n";
				
				$sql_ranges = $dbh->prepare("SELECT DISTINCT ranges FROM organisations WHERE id = $org");
				$result_ranges = $sql_ranges->execute();
				@rangerow = $sql_ranges->fetchrow_array;
				@rangerow = split(/;/, "@rangerow");
				$count = @rangerow;
				if ($count > 0) {
					foreach $range (@rangerow) {
						# Get details about the attacks and print them to mail.
						# Printed in format: ip address attacker, time of attack, type of attack.
						$message = "";
						$sql = "SELECT DISTINCT source, timestamp, text FROM attacks, sensors, details WHERE attacks.source <<= '$range' AND details.attackid = attacks.id AND details.type = '1' AND attacks.severity = '1' AND attacks.timestamp >= '$ts_start' AND attacks.timestamp <= '$ts_end' AND attacks.sensorid = sensors.id AND sensors.organisation = '$org' $sensor_where GROUP BY source, timestamp, text";
						$ipview_query = $dbh->prepare($sql);
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
				} else {
					print MAIL "No malicious attacks detected from your ranges for last timespan.\n";
				}
			}
			# THRESHOLD:
			elsif ($template == 3) {
				# Get detailed data for threshold
				$sql = "SELECT target, value, deviation, operator FROM report_template_threshold WHERE report_content_id = '$id'";
				$detail_query = $dbh->prepare($sql);
				$execute_result = $detail_query->execute();
				@detail = $detail_query->fetchrow_array;
				$target = $detail[0];
				$db_timespan = $frequency;
				$db_value = $detail[1];
				$deviation = $detail[2];
				$db_operator = $detail[3];
				
				if ($target == 1) {
					# target = Number malicious attacks
					
					# Timespan: 1=last hour, 2=last day, 3=last week
					# Set start timestamp
					if ($db_timespan == 1) { $timespan = $hour; }
					elsif ($db_timespan == 2) { $timespan = $day; }
					else { $timespan = $week; }
					$ts_start = ($ts_now - $timespan);
					$ts_end = $ts_now;
					
					print MAIL "Results from " . getdatetime($ts_start) . " till " . getdatetime($ts_end) . "\n";
					print MAIL "\n";
					
					# Operator
					@ar_operator = ('', '<', '>', '<=', '>=', '=', '!=');
					$operator = $ar_operator[$db_operator];
					
					# Value
					# -1 = average, other value = user defined
					if ($db_value > -1) {
						$value = $db_value;
					} else {
						# Get average value for this timespan
						# 2 possibilities: use db_table stats_history of attacks
						# Now using stats_history
						$sql = "SELECT SUM(count_malicious) AS total, COUNT(month) AS nr_months FROM stats_history, sensors WHERE stats_history.sensorid = sensors.id AND sensors.organisation = '$org' $sensor_where";
						$avg_query = $dbh->prepare($sql);
						$execute_result = $avg_query->execute();
						@avg = $avg_query->fetchrow_array;
						
						$total = $avg[0];
						$nr_months = $avg[1];
						$average = floor($total / $nr_months);
						# Average for 1 month
						# Assume 1 month =~ 30 days
						if ($timespan == $hour) {
							$value = floor($average / 30 / 24);
						} elsif ($timespan == $day) {
							$value = floor($average / 30);
						} 
					}
					
					# Get current value for last timespan
					$sql = "SELECT COUNT(attacks.id) FROM attacks, sensors WHERE sensors.id = attacks.sensorid AND sensors.organisation = '$org' AND timestamp >= '$ts_start' AND timestamp <= '$ts_end'";
					$check_query = $dbh->prepare($sql);
					$execute_result = $check_query->execute();
					@db_row = $check_query->fetchrow_array;
					$db_value = $db_row[0];
					
					# Use deviation to set db_upper and db_lower values
					$perc = ($deviation / 100);
					$db_upper = ($db_value + ($db_value * $perc));
					$db_lower = ($db_value - ($db_value * $perc));
					
					$send = 0;
					if ($operator == '<') { 
						if ($value < $db_lower) { $send = 1; }
					} elsif ($operator == '<=') {
						if ($value <= $db_lower) { $send = 1; }
					} elsif ($operator == '>') {
						if ($value > $db_upper) { $send = 1; }
					} elsif ($operator == '>=') {
						if ($value >= $db_upper) { $send = 1; }
					} elsif ($operator == '=') {
						if (($value >= $db_lower) && ($value <= $db_upper)) { $send = 1; }
					} elsif ($operator == '!=') {
						if (($value < $db_lower) && ($value > $db_upper)) { $send = 1; }
					}
					
					if ($send == 1) {
						# Send an e-mail
						print MAIL "Triggered threshold report: $title\n";
						print MAIL "\n";
						print MAIL "Use next link to view related attacks:\n";
						print MAIL $webinterface_prefix . "/logsearch.php?from=$ts_start&to=$ts_end&f_reptype=multi&f_submit=Search";
						print MAIL "\n";
					} else {
						# Free file
						close(MAIL);
						# Remove file
						system "rm $mailfile";
					}
				}			
			}
			
			if ($send == 1) {
				print MAIL "\n";
				close(MAIL);
				
				# Update last_sent
				$last_sent = time;
				$sql = "UPDATE report_content SET last_sent = '$last_sent' WHERE id = '$id'";
		    		$execute_result = $dbh->do($sql);
	    		
				&sendmail($email, $id, $subject, $priority, $gpg_enabled);
			}
		}
	}
	$last_sent = "";
}

sub sendmail {
	# Get variables : mailaddress to send to, Date, sender, recipient, subject and your SMTP mailhost
	$email = $_[0];
	$id = $_[1];
	$subject = $_[2];
	$priority = $_[3];
	$gpg_enabled = $_[4];
	
	print "Sending mailreport to $email\n";
	
	$maildata = "/tmp/" .$id. ".mail";
	$sigmaildata = "$maildata" . ".sig";
	$from_address = $from_address;
	$to_address = "$email";
	$mail_host = 'localhost';
	
	# Prepare subject
	# Ex. SURFnet IDS stats for %date%
	# %date%, %day%, %time%, %hour%
	$sub_date = getdate(time);
	$sub_time = gettime(time);
	$sub_tm = localtime(time);
	$sub_hour = $sub_tm->hour . "h";
	@ar_day = ('Sunday', 'Monday', 'Thuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday');
	$sub_day = $ar_day[$sub_tm->wday];
	$subject =~ s/%date%/$sub_date/;
	$subject =~ s/%time%/$sub_time/;
	$subject =~ s/%hour%/$sub_hour/;
	$subject =~ s/%day%/$sub_day/;

	if ($gpg_enabled == 1) {
		# Encrypt the mail with gnupg 
		$gpg = new GnuPG();
		$gpg->clearsign( plaintext => "$maildata", output => "$sigmaildata",
	                     armor => 1, passphrase => $passphrase
	                     );
	}
	
	#### Create the multipart container
	$msg = MIME::Lite->new (
		From => $from_address,
		To => $to_address,
		Subject => $subject,
		Type => 'multipart/mixed'
	) or die "Error creating multipart container: $!\n";
	
	# Prepare priority (1 = low, 2 = normal, 3 = high)
	if ($priority == 1) { $header_priority = "5 (Lowest)"; }
	elsif ($priority == 3) { $header_priority = "1 (Highest)"; }
	else { $header_priority = "3 (Normal)"; }
	$msg->add('X-Priority' => $header_priority);
	
	if ($gpg_enabled == 1) { $final_maildata  = $sigmaildata; }
	else { $final_maildata = $maildata; }
	### Add the (signed) file
	$msg->attach (
		Type => 'text/plain; charset=ISO-8859-1',
		Path => $final_maildata,
		Filename => $final_maildata,
	) or die "Error adding $final_maildata: $!\n";
	
	### Send the Message
	#  MIME::Lite->send('smtp', $mail_host, Timeout=>60, Hello=>"$mail_hello", From=>"$from_address");
	MIME::Lite->send('sendmail');
	$msg->send;
	
	# Print info to a log file
	$localtime = time();
	$localtime = getdatetime($localtime);
	print LOG "[$localtime] Mailed stats for $sub_date to: $email with organisation $org\n";
	
	# Delete the mail and signed mail
	system "rm $maildata";
	system "rm $final_maildata";
}

# Closing database connection.
close(LOG);

