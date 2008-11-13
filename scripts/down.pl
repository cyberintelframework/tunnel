#!/usr/bin/perl

use warnings;
use strict 'vars';

#########################################
# Stop script for IDS server            #
# SURFnet IDS 2.10.00                   #
# Changeset 002                         #
# 15-07-2008                            #
# Jan van Lith & Kees Trippelvitz       #
# Auke Folkerts (changeset 003)         #
#########################################

#####################
# Changelog:
# 003 - Support for multiple vlans per tunnel
#     - various cleanups
# 002 Added logsys stuff
# 001 version 2.10.00 release
#####################


#####################
# Includes
####################
use vars qw ($c_surfidsdir);
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";


####################
# Modules used
####################
use DBI;
use Time::localtime qw(localtime);


####################
# Global variables
####################
our $source = 'down.pl';
our $sensor = $ENV{sensor} || die ("no sensor");
our $tap = $ENV{tap} || die ("no tap");
our $remoteip = $ENV{remoteip} || die ("no remoteip");
our $pid = $ENV{pid} || die ("no pid");


####################
# Main script
###################
my $result = connectdb();
if ($result eq 'false') {
	die ("No database connection");
}


logsys(LOG_DEBUG, "SCRIPT_START");


# find all tap devices in use
my $res = dbquery("SELECT tap FROM sensors WHERE keyname = '$sensor' AND status = 1");
my @devices;
for (my $i = 0; $i < $res->rows(); $i++) {
	my @row = $res->fetchrow_array;
	my $dev = $row[0];
	push (@devices, $dev);
	logsys(LOG_DEBUG, "SPEC", "$dev added");
}



# Update database. Clear the tap and tapip fields for all entries for this sensor.
dbquery("UPDATE sensors SET tap = '', tapip = '0.0.0.0' WHERE keyname = '$sensor'");


# Update dabase. Set the status field to 0 for all active clients. This
# is a safety net in case the stopclient.php script is not run by the 
# sensor (ie. it is crashed). down.pl will be called any time an openvpn
# connection drops.
dbquery("UPDATE sensors SET status = 0 WHERE keyname = '$sensor' AND status = 1");


# For all tap devices affected by the openvpn tunnel going down, clean up.
# (this uses the array of affected devices created earlier in this script)
foreach my $dev (@devices) {
	# Stop DHCP. Does nothing for staticcaly configured clients.
	killdhclient($dev);

	# Delete .leases file
	sys_exec("rm -f /var/lib/dhcp3/$dev.leases");

	# Fix routes
	$result = deliprules($dev);
	if ($result) {
		logsys(LOG_WARN, "SYS_FAIL", "Deleting ip rules for $dev failed (error code $result)");
	} else {
		logsys(LOG_DEBUG, "NOTIFY", "Removed routing table for $dev");
	}


	# Flush the routing table of the tap device just to be sure.
	$result = flushroutes($dev);
	if ($result) {
		logsys(LOG_WARN, "SYS_FAIL", "Flushing routes for $dev failed. (error code ($result)");
	} else {
		logsys(LOG_DEBUG, "NOTIFY", "Flushed routes for $dev");
	}
}


# Delete route to connecting ip address of client via local gateway.
sys_exec("route del -host $remoteip");
if ($?) {
	logsys(LOG_ERROR, "NETWORK_ERROR", "Failed  to delete host route (error code $?)");
	exit(1);
} else{ 
	logsys(LOG_DEBUG, "NOTIFY", "Deleted host route for $remoteip.");
}


END {
	logsys(LOG_DEBUG, "SCRIPT_END");
	disconnectdb();
}
