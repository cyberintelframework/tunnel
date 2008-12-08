#!/usr/bin/perl

use warnings;
use strict 'vars';

####################################
# Setmac script for tunnel server  #
# SURFids 2.10                     #
# Changeset 003                    #
# 08-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
# Auke Folkerts (changeset 003)    #
####################################

#####################
# Changelog:
# 003 support for multiple vlans per tunnel
# 002 Added logsys stuff
# 001 version 2.10.00 release
#####################

##############
# Includes
#############
use vars qw ($c_surfidsdir);
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);

####################
# Global variables 
####################
our $source = 'setmac.pl';
our $sensor = $ENV{sensor} || die ("no sensor");
our $tap = $ENV{tap} || die ("no tap");
our $remoteip = $ENV{remoteip} || die ("no remoteip");
our $pid = $ENV{pid} || die ("no pid");

##################
# Main script
##################
my $result = connectdb();
if ($result eq 'false') {
	die ("No database connection");
}

logsys(LOG_DEBUG, "SCRIPT_START");

# Check for tap existance.
my $ret = sys_exec("ifconfig $tap");
if ($ret != 0) {
	logsys(LOG_ERROR, "NO_DEVICE", "Tap device '$tap' does not exist!");
	exit(1);
}

# Update sensor records. 
my $date = time();
dbquery("UPDATE sensors SET status = 1, laststart = $date WHERE status = 0 AND keyname = '$sensor'");

# Make sure the real tap device is stored in the database on the 
# (inactive) non-tagged sensor-entry. This info is later used to 
# break down the tunnel. 
dbquery("UPDATE sensors SET tap = '$tap' WHERE keyname = '$sensor' and vlanid = '0'");

# Get the vlans configured for this sensor (vlan = 0 means no vlans)
my $res = dbquery("SELECT vlanid FROM sensors WHERE keyname = '$sensor' AND status = 1");

# Iterate over all configured entries.  For normal sensors, this is one(1) entry. 
# For VLAN-sensors, this is one entry per vlan.
for (my $i = 0; $i < $res->rows(); $i++) {
	my @row = $res->fetchrow_array;
	my $vlan = $row[0];
	my $dev;

	# Create device if needed
	if ($vlan != 0) {
		logsys(LOG_DEBUG, "NOTIFY", "New vlan interface: $tap.$vlan...");
		sys_exec("vconfig add $tap $vlan");
		$dev = "$tap.$vlan";
	} else{ 
		$dev = "$tap";
	}

	# Make sure device has a unique MAC address
	my $mac = dbmacaddr("$sensor", "$remoteip", $vlan);
	if ("$mac" eq "false") {
		# If no mac address is present in the database, add the 
		# generated one from OpenVPN to the database.
		logsys(LOG_DEBUG, "NO_MAC_ADDR", "No MAC address in sensors table for $dev!");
		$mac = `ifconfig $dev | grep HWaddr | awk '{print \$5}'`;
		chomp($mac);

		# Generate a new mac address where the last 2 bytes indicate the vlan.
		my @macparts = split(":", $mac);
		$#macparts -= 2; # chomp off last 2 elements
		my ($a,$b) = (int($vlan/256), $vlan%256);
		$a = sprintf("%x", $a);
		$b = sprintf("%x", $b);
		push (@macparts, ($a,$b));
		$mac = join(":", @macparts);

		logsys(LOG_INFO, NEW_MAC_ADDR, "Generated new MAC for $dev: $mac");
		dbquery("UPDATE sensors SET mac = '$mac' WHERE keyname = '$sensor' AND vlanid = '$vlan'");
	}

	# Set mac address
	sys_exec("ifconfig $dev hw ether $mac");

	# Bring the device up.
	sys_exec("ifconfig $dev up");
}

# At this point, all vlan interfaces exist, are UP, and have a unique 
# hardware address. Call sql.pl to obtain IP addresses for each interface.
system("$c_surfidsdir/scripts/sql.pl $tap $sensor &");

################
# Exit handler! 
################
END {
	logsys(LOG_DEBUG, "SCRIPT_END");
	disconnectdb();
}
