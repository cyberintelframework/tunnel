#!/usr/bin/perl

#use warnings;
#use strict 'vars';

####################################
# OpenVPN wrapper                  #
# SURFids 2.10                     #
# Changeset 001                    #
# 08-12-2008                       #
# Auke Folkerts                    #
####################################

#
# tcp-wrapper.pl is a wrapper around openvpn. It is started from xinetd. The goal 
# is to get the sensorname from the database (based on the remote ip) and to start 
# openvpn so that it uses the sensor name as the tap device name (instead of eg. 
# 'tap14'). Furthermore, this script makes sure that the sensor name, the tap device,
# the remote_ip, and the process ID are set in the environment, so that scripts
# run from openvpn (up.pl for new connections, down.pl for tunnels that are taken
# down etc.) have this information available.
# 

#####################
# Changelog:
# 001 version 2.10
#####################

##########################
# Includes
#########################
#use vars qw ($c_surfidsdir);
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);

########################
# Global variables
######################
our $source = "tcp-wrapper.pl";
our $sensor;
our $tap;
our $remoteip;
our $pid = $$;

##################
# Main script
##################
$remoteip = $ENV{REMOTE_HOST} || die ("no remote host");
 
my $res = dbconnect();
if ($res eq 'false') {
	die ("No database connection");
}

# Get the sensorname from the database (based on the remoteip)
my $sql;
$sql = "SELECT distinct sensors.keyname, status FROM sensor_details, sensors ";
$sql .= " WHERE sensors.keyname = sensor_details.keyname AND remoteip = '$remoteip' AND NOT status = 3";
$res = dbquery($sql);
my $numrows= $res->rows();
if ($numrows == 1) {
    my @row = $res->fetchrow_array;
    $sensor = $row[0];
    $status = $row[1];
    $dev = $sensor;
    $dev =~ s/sensor/s/;

    if ($status == 1) {
        logsys($f_log_warn, "CONN_DUP", "Sensor was already running, additional connections ignored");
        exit(1);
    }

    # Set the status to starting up (6)
    $sql = "UPDATE sensors SET status = 6 WHERE keyname = '$sensor' AND NOT status = 3";
    $res = dbquery($sql);
    logsys($f_log_debug, "STATUS_CHANGE", "Set status to 6 for $sensor");
    logsys($f_log_info, "CONN_OK", "Connection accepted for $sensor with IP address $remoteip");
} elsif ($numrows > 1) {
    logsys($f_log_error, "IP_OVERLOAD", "Multiple sensors ($numrows) for $remoteip. Refusing connection");
    exit(1);
} else {
    logsys($f_log_error, "CONN_DENIED", "Connect from $remoteip refused");
    exit(1);
}

my $openvpn = "/usr/sbin/openvpn";
my $environment = "--setenv sensor $sensor --setenv tap $dev --setenv remoteip $remoteip --setenv pid $pid";
my $arguments = "--config /etc/surfnetids/openvpn.conf";

my $command = "$openvpn $environment $arguments";

if ($sensor eq "") {
	$command .= " --dev tap";
} else {
	$command .= " --dev $dev --dev-type tap";
}
logsys($f_log_debug, "EXEC", "Starting openvpn: $command");

exec("$command");
die "exec failed: $!";

END {
	logsys($f_log_debug, "SCRIPT_END");
    dbdisconnect();
}
