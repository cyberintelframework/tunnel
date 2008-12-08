#!/usr/bin/perl

use warnings;
use strict 'vars';

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
use vars qw ($c_surfidsdir);
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
 
my $res = connectdb();
if ($res eq 'false') {
	die ("No database connection");
}

# Get the sensorname from the database (based on the remoteip)
$res = dbquery("SELECT keyname FROM sensors WHERE remoteip = '$remoteip'");
if ($res->rows) { 
	my @row = $res->fetchrow_array;
	$sensor = $row[0];
} else {
	logsys(LOG_WARN, "UNKNOWN_IP", "Connect from $remoteip refused");
	exit(1);
}

my $openvpn = "/usr/sbin/openvpn";
my $environment = "--setenv sensor $sensor --setenv tap $sensor --setenv remoteip $remoteip --setenv pid $pid";
my $arguments = "--config /etc/openvpn/server.conf";

my $command = "$openvpn $environment $arguments";

if ($sensor eq "") {
	$command .= " --dev tap";
} else {
	$command .= " --dev $sensor --dev-type tap";
}
logsys(LOG_DEBUG, "NOTIFY", "Starting openvpn: '$command'");

exec("$command");
die "exec failed: $!";

END {
	logsys(LOG_DEBUG, "SCRIPT_END");
	disconnectdb();
}
