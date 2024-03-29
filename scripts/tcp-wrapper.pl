#!/usr/bin/perl

####################################
# OpenVPN wrapper                  #
# SURFids 3.00                     #
# Changeset 003                    #
# 07-07-2009                       #
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
# 003 Removed debug message
# 002 Added check for sensors in tunnel server network
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

if ($ARGV[0]) {
  if ($ARGV[1]) {
    $chk = in_network($remoteip, $ARGV[0], $ARGV[1]);
    if ($chk eq "True") {
        logsys($f_log_error, "CONN_DENIED", "Remote sensors cannot be run in the same network as the server. See FAQ T27.");
        exit(1);
    }
  }
}

# Get the sensorname from the database (based on the remoteip)
my $sql;
$sql = "SELECT DISTINCT sensors.keyname, status FROM sensor_details, sensors ";
$sql .= " WHERE sensors.keyname = sensor_details.keyname AND remoteip = '$remoteip' AND NOT status = 3";
$res = dbquery($sql);
my $numrows= $res->rows();
if ($numrows == 1) {
    my @row = $res->fetchrow_array;
    $sensor = $row[0];
    $status = $row[1];
    $dev = $sensor;
    $dev =~ s/sensor/s/;

    `ifconfig $dev 2>/dev/null`;
    if ($? == 0) {
        logsys($f_log_warn, "CONN_DUP", "Sensor was already running, additional connections ignored");
        exit(1);
    }

    # Set the status to starting up (6)
    $sql = "UPDATE sensors SET status = 6 WHERE keyname = '$sensor' AND NOT status = 3";
    $res = dbquery($sql);
    logsys($f_log_debug, "STATUS_CHANGE", "Set status to 6 for $sensor");
    logsys($f_log_info, "CONN_OK", "Connection accepted for $sensor with IP address $remoteip");
} elsif ($numrows > 1) {
    logsys($f_log_error, "CONN_DENIED", "Multiple sensors ($numrows) for $remoteip. Refusing connection");
    exit(1);
} else {
    logsys($f_log_error, "CONN_DENIED", "Connect from $remoteip refused");
    exit(1);
}

my $openvpn = "/usr/sbin/openvpn";
my $environment = "--setenv sensor $sensor --setenv tap $dev --setenv remoteip $remoteip --setenv pid $pid --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
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
