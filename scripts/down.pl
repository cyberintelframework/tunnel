#!/usr/bin/perl

#use warnings;
#use strict 'vars';

####################################
# Down script                      #
# SURFids 2.10                     #
# Changeset 003                    #
# 08-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
# Auke Folkerts (changeset 003)    #
####################################

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
#use vars qw ($c_surfidsdir $f_log_debug $f_log_info $f_log_warn $f_log_error $f_log_crit);
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
my $result = dbconnect();
if ($result eq 'false') {
	die ("No database connection");
}

logsys($f_log_debug, "SCRIPT_START");

# find all tap devices in use
my $res = dbquery("SELECT tap FROM sensors WHERE keyname = '$sensor' AND status = 1");
my @devices;
for (my $i = 0; $i < $res->rows(); $i++) {
	my @row = $res->fetchrow_array;
	my $dev = $row[0];
	push (@devices, $dev);
}

# Update database. Clear the tap and tapip fields for all entries for this sensor.
dbquery("UPDATE sensors SET tap = '', tapip = '0.0.0.0' WHERE keyname = '$sensor'");

# Update database. Save the uptime for each vlan, and set the status to offline (=0).
my $date = time();
dbquery("UPDATE sensors SET laststop = $date  WHERE keyname = '$sensor' AND status > 0 AND NOT status = 3");
dbquery("UPDATE sensors SET uptime = uptime + laststop - laststart, status = 0 WHERE keyname = '$sensor' AND status > 0 AND NOT status = 3");

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
		logsys($f_log_warn, "SYS_FAIL", "Deleting ip rules for $dev failed (error code $result)");
	} else {
		logsys($f_log_debug, "NOTIFY", "Removed ip rules for $dev");
	}


	# Flush the routing table of the tap device just to be sure.
	$result = flushroutes($dev);
	if ($result) {
		logsys($f_log_warn, "SYS_FAIL", "Flushing routes for $dev failed. (error code ($result)");
	} else {
		logsys($f_log_debug, "NOTIFY", "Flushed routes for $dev");
	}
}

# Delete route to connecting ip address of client via local gateway.
sys_exec("route del -host $remoteip");
if ($?) {
	logsys($f_log_error, "NETWORK_ERROR", "Failed  to delete host route (error code $?)");
	exit(1);
} else{ 
	logsys($f_log_debug, "NOTIFY", "Deleted host route for $remoteip.");
}


END {
	logsys($f_log_debug, "SCRIPT_END");
	dbdisconnect();
}
