#!/usr/bin/perl

##########################################
## SURFids 2.10.00                       #
## Changeset 006                         #
## 19-08-2008                            #
## Jan van Lith & Kees Trippelvitz       #
## Auke Folkerts (changeset 007)         #
##########################################
## Contributors:                         #
## Peter Arts                            #
##########################################

######################
## Changelog:
## 007 Support multiple vlans per tunnel
## 006 Error check on duplicate tap's
## 005 Passing along sensorid to detectarp.pl
## 004 Added logsys stuff
## 003 Destroying statement handle before disconnecting
## 002 Don't update the tapip if statically configured
## 001 version 2.10.00 release
######################


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


####################
## Global variables 
#####################
our $source = 'sql.pl';
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


# Get the IP address configuration for the tap device from the database.
$res = dbquery("SELECT netconf, netconfdetail, vlanid, arp, id FROM sensors WHERE keyname = '$sensor' AND status = 1");
if ($res->rows == 0) {
	# no records
	logsys(LOG_ERROR, "NO_SENSOR_RECORD", "No entries for '$sensor' are configured" );
	exit(1);
}


for($i = 0; $i < $res->rows; $i++) {
	my @row = $res->fetchrow_array;

	my $netconf = $row[0];
	my $netconfdetail = $row[1];
	my $vlanid = $row[2];
	my $arp = $row[3];
	my $sensorid = $row[4];
	my $dev;

	# The device we're going to work with is something like tap0 or tap0.13,
	# depending on wether we're using vlans (latter) or not (former).
	if ($vlanid != 0) {
		$dev = "$tap.$vlanid";
	} else {
		$dev = "$tap";
	}
	logsys(LOG_DEBUG, "NOTIFY", "Configuring $tap: Vlan=$vlanid, config=$netconf-$netconfdetail");


	# Kill off any remaining dhcp daemons for this interface
	killdhclient($dev);  


	# Make sure the routing table exists for this device. The startstatic()
	# function, and surfnetids-dhclient will adapt routing rules dynamically,
	# and require that /etc/iproute2/rt_tables contains the device. 
	my $exist = `grep $dev /etc/iproute2/rt_tables | wc -l`;
	if ($exist == 0) {
		my $next_identifier = `tail -1 /etc/iproute2/rt_tables | awk '{print \$1}'`;
		chomp($next_identifier);
		$next_identifier++;
		`echo "$next_identifier			$dev" >> /etc/iproute2/rt_tables`;
		logsys(lOG_DEBUG, "NOTIFY", "Added entry for $dev in /etc/iproute2/rt_tables (id $next_identifier)");
	} elsif ($exist > 1) {
		logsys(LOG_WARN, "NOTITY", "/etc/iproute2/rt_tables contains multiple lines for $dev. Please check sql.p");
	}

	if ($netconfdetail eq "dhcp") {
		# Start the dhcp client
		startdhcp($dev);

	} else { 
		# Set static network configuration without gateway, dns and resolv.conf
		# Format of netconfig: ip|netmask|gateway|broadcast
		my @netconfig = split(/\|/, $netconfdetail);

		my $if_ip = $netconfig[0];
		my $if_nw = $netconfig[1];
		my $if_gw = $netconfig[2];
		my $if_bc = $netconfig[3];

		startstatic($dev, $if_ip, $if_nw, $if_gw, $if_bc);
	}


	# check wether interface obtained an IP
	my $result = check_interface_ip($dev, $c_sql_dhcp_retries);
	if ($result) {
		logsys(LOG_ERROR, "NETWORK_ERROR", "Device '$dev' failed to come up");
		exit(1);
	}
	logsys(LOG_DEBUG, "$dev device is up.");


	# Get the IP address from the tap interface.
	my $tap_ip = getifip($dev);
	logsys(LOG_DEBUG, "NOTIFY",  "Tap device '$dev' obtained IP address $tap_ip");


	# Update Tap info to the database for the current vlan.
	dbquery("UPDATE sensors SET tap = '$dev', tapip = '$tap_ip' WHERE keyname = '$sensor' and vlanid = '$vlanid'");


	if ($c_enable_pof == 1) {
		system "p0f -d -i $tap -o /dev/null";
		logsys(LOG_INFO, "NOTIFY", "Started 'p0f -d -i $tap -o /dev/null'");
	}

	if ($c_enable_arp == 1 && $arp == 1) {
		system("$c_surfidsdir/scripts/detectarp.pl $tap &");
		logsys(LOG_INFO, "NOTIFY", "Started detectarp.pl $tap");
	}
}


END {
	logsys(LOG_DEBUG, "SCRIPT_END");
	disconnectdb();
}
