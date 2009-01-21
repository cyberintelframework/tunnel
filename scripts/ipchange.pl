#!/usr/bin/perl

####################################
# SURFids 2.10                     #
# Changeset 007                    #
# 08-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################
# Contributors:                    #
# Peter Arts                       #
# Auke Folkerts (changeset 007)    #
####################################

use warnings;
use strict "vars";

###########################
## NOTE NOTE NOTE NOTE ####
###########################
#
# OpenVPN will only allow traffic through the tunnel once
# this script has returned! This means that we can't obtain
# a dhcp lease from within this script. 
#
# To counter this, we daemonize this script so that it 
# continues its execution in the background
##########################

#####################
# Changelog:
# 007 Support multiple vlans per tunnel
# 006 Error check on duplicate tap's
# 005 Passing along sensorid to detectarp.pl
# 004 Added logsys stuff
# 003 Destroying statement handle before disconnecting
# 002 Don't update the tapip if statically configured
# 001 version 2.10.00 release
#####################

##################
# Includes
##################
use vars qw($c_surfidsdir $c_sql_dhcp_retries $c_enable_pof $c_enable_arp);
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime); 

# Make sure we have a database connection
my $result = dbconnect();
if ($result eq 'false') {
    print "No database connection";
    exit(6);
}

####################
## Global variables 
#####################
if (!$ENV{sensor}) { logsys(LOG_ERROR, "ENV_FAIL", "No sensor name in environment"); exit(2); }
if (!$ENV{tap}) { logsys(LOG_ERROR, "ENV_FAIL", "No tap device name in environment"); exit(3); }
if (!$ENV{remoteip}) { logsys(LOG_ERROR, "ENV_FAIL", "No remote IP address in environment"); exit(4); }
if (!$ENV{pid}) { logsys(LOG_ERROR, "ENV_FAIL", "No process ID in environment"); exit(5); }
our $source = 'ipchange.pl';
our $sensor = $ENV{sensor} || die ("no sensor");
our $tap = $ENV{tap} || die ("no tap");
our $remoteip = $ENV{remoteip} || die ("no remoteip");
our $pid = $ENV{pid} || die ("no pid");
our $g_vlanid = 0;

##################
# Main script
##################
my $mypid;
if (!$mypid) {
  logsys(LOG_DEBUG, "SCRIPT_START");
}

# Fork to the background
($mypid = fork) and exit;

$result = dbconnect();
if ($result eq 'false') {
    print "No database connection";
    exit(6);
}

# Get the IP address configuration for the tap device from the database.
my $res = dbquery("SELECT networkconfig, vlanid, arp, id FROM sensors WHERE keyname = '$sensor' AND status > 0 AND NOT status = 3");
if ($res->rows == 0) {
	# no records
	logsys(LOG_ERROR, "NO_SENSOR_RECORD", "No entries for $sensor are configured" );
	exit(1);
}

for(my $i = 0; $i < $res->rows; $i++) {
	my @row = $res->fetchrow_array;

	my $netconf = $row[0];
#	my $netconfdetail = $row[1];
	my $vlanid = $row[1];
    $g_vlanid = $vlanid;
	my $arp = $row[2];
	my $sensorid = $row[3];
	my $dev;

	# The device we're going to work with is something like tap0 or tap0.13,
	# depending on wether we're using vlans (latter) or not (former).
	if ($vlanid != 0) {
		$dev = "$tap.$vlanid";
	} else {
		$dev = "$tap";
	}
	logsys(LOG_DEBUG, "NOTIFY", "Bringing up $dev: $netconf");


    logsys(LOG_DEBUG, "NOTIFY", "Going to kill dhclient for $dev");
	# Kill off any remaining dhcp daemons for this interface
	killdhclient($dev);
    logsys(LOG_DEBUG, "NOTIFY", "Killed dhclient for $dev");


	# Make sure the routing table exists for this device. The startstatic()
	# function, and surfnetids-dhclient will adapt routing rules dynamically,
	# and require that /etc/iproute2/rt_tables contains the device. 
    my $esc_dev = escape_dev($dev);
	my $exist = `grep '\\b$esc_dev\\b' /etc/iproute2/rt_tables | wc -l`;
	if ($exist == 0) {
		my $next_identifier = `tail -1 /etc/iproute2/rt_tables | awk '{print \$1}'`;
		chomp($next_identifier);
		$next_identifier++;
		`echo "$next_identifier			$dev" >> /etc/iproute2/rt_tables`;
		logsys(LOG_DEBUG, "NOTIFY", "Added entry for $dev in /etc/iproute2/rt_tables (id $next_identifier)");
	}

	if ($netconf eq "dhcp") {
		# Start the dhcp client
		startdhcp($dev);

	} else { 
		# Set static network configuration without gateway, dns and resolv.conf
		# Format of netconfig: ip|netmask|gateway|broadcast
		my @netconfig = split(/\|/, $netconf);

		my $if_ip = $netconfig[0];
		my $if_nw = $netconfig[1];
		my $if_gw = $netconfig[2];
		my $if_bc = $netconfig[3];

		startstatic($dev, $if_ip, $if_nw, $if_gw, $if_bc);
	}


	# check wether interface obtained an IP
	my $result = check_interface_ip($dev, $c_sql_dhcp_retries);
	if ($result) {
		logsys(LOG_ERROR, "NETWORK_ERROR", "Device $dev failed to come up");
		exit(1);
	}
	logsys(LOG_DEBUG, "NOTICE", "$dev device is up.");


	# Get the IP address from the tap interface.
	my $tap_ip = getifip($dev);
	logsys(LOG_DEBUG, "NOTIFY",  "Tap device $dev obtained IP address $tap_ip");


	# Update Tap info to the database for the current vlan.
	dbquery("UPDATE sensors SET tap = '$dev', tapip = '$tap_ip', status = 1 WHERE keyname = '$sensor' and vlanid = '$vlanid'");


	if ($c_enable_pof == 1) {
		system "p0f -d -i $dev -o /dev/null";
		logsys(LOG_INFO, "NOTIFY", "Started passive TCP fingerprinting");
	}

	if ($c_enable_arp == 1 && $arp == 1) {
		system("$c_surfidsdir/scripts/detectarp.pl $dev &");
		logsys(LOG_INFO, "NOTIFY", "Started ARP & Rogue DHCP detection");
	}
}
$g_vlanid = 0;


END {
  if ($mypid) {
    logsys(LOG_DEBUG, "NOTIFY", "Daemonized");
  } else {
    logsys(LOG_DEBUG, "NOTIFY", "Last return code: $?");
    logsys(LOG_DEBUG, "SCRIPT_END");
    dbdisconnect();
  } 
}
