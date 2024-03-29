#!/usr/bin/perl

#use warnings;
#use strict "vars";

####################################
# Startup script for tunnel server #
# SURFids 3.00                     #
# Changeset 004                    #
# 21-10-2009                       #
# Jan van Lith & Kees Trippelvitz  #
# Auke Folkerts (changeset 003)    #
####################################

#####################
# Changelog:
# 004 Removed -w switch
# 003 support multiple vlans per tunnel
# 002 Added logsys stuff
# 001 version 2.10.00 release
#####################

############
# Includes  
############
#use vars qw ($c_surfidsdir);
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Modules used
##################
use Time::localtime qw(localtime);
use DBI;

# Make sure we have a database connection
my $result = dbconnect();
if ($result eq 'false') {
    die ("No database connection");
}

##################
# Global variables
# ################
if (!$ENV{sensor}) { logsys($f_log_error, "ENV_FAIL", "No sensor name in environment"); exit(2); }
if (!$ENV{tap}) { logsys($f_log_error, "ENV_FAIL", "No tap device name in environment"); exit(3); }
if (!$ENV{remoteip}) { logsys($f_log_error, "ENV_FAIL", "No remote IP address in environment"); exit(4); }
if (!$ENV{pid}) { logsys($f_log_error, "ENV_FAIL", "No process ID in environment"); exit(5); }
our $source = "up.pl";	
our $sensor = $ENV{sensor} || die ("no sensor");
our $tap = $ENV{tap} || die ("no tap");
our $remoteip = $ENV{remoteip} || die ("no remoteip");
our $pid = $ENV{pid} || die ("no pid");
our $g_vlanid = 0;

###############
# Main script 
###############
logsys($f_log_debug, "SCRIPT_START");


# Check for leftover source based routing rules and delete them.
my $delresult = deliprules($tap);


# Check for leftover source based routing tables and delete if present.
my $chk = chkrule($tap);
if ($chk > 0) {
    logsys($f_log_warn, "IP_RULE", "Leftover rules: $chk");
    my $flushresult = flushroutes($tap);
    if ($flushresult) {
	    logsys($f_log_warn, "SYS_FAIL", "Flushing routes for $tap failed");
    }
}


# Check for tap existance.
my $ret = sys_exec("ifconfig $tap");
if ($ret != 0) {
    logsys($f_log_error, "DEV_INFO", "Tap device $tap does not exist!");
    exit(1);
}


# bring tap interface up. 
sys_exec("ifconfig $tap up");
if ($?) {
	logsys($f_log_error, "DEV_INFO", "Failed to bring up device $tap (error code $?)");
	exit(1);
}


# Make sure the real tap device is stored in the database on the 
# (inactive) non-tagged sensor-entry. This info is later used to 
# break down the tunnel. 
dbquery("UPDATE sensors SET tap = '$tap' WHERE keyname = '$sensor' and vlanid = '0'");


# Get the sensor type
my $res = dbquery("SELECT sensortype FROM sensor_details WHERE keyname = '$sensor'");
if ($res->rows()) {
    my @row = $res->fetchrow_array;
    my $sensortype = $row[0];
    logsys($f_log_debug, "SENSOR_INFO", "Detected sensor type: $sensortype");
} else {
    logsys($f_log_error, "SENSOR_INFO", "Missing sensor type in the database");
    exit(1);
}

# Get the vlans configured for this sensor (vlan = 0 means no vlans). For each
# VLAN (if any) make sure the correct device is created and has a unique
# hardware address
$res = dbquery("SELECT vlanid FROM sensors WHERE keyname = '$sensor' AND status > 0 AND NOT status = 3");
for (my $i = 0; $i < $res->rows(); $i++) {
    my @row = $res->fetchrow_array;
    my $vlan = $row[0];
    $g_vlanid = $vlan;
    my $dev;

    # Create device if needed
    if ($vlan != 0) {
        logsys($f_log_debug, "DEV_INFO", "New vlan interface: $tap.$vlan...");
        sys_exec("vconfig add $tap $vlan");
        $dev = "$tap.$vlan";
    } else{
        $dev = "$tap";
    }

    # Make sure device has a unique MAC address
    my $mac = dbmacaddr("$sensor", $vlan);
    if ("$mac" eq "false") {
        # If no mac address is present in the database, add the 
        # generated one from OpenVPN to the database.
        logsys($f_log_debug, "MAC_INFO", "No MAC address in sensors table for $dev!");

        #$mac = `ifconfig $dev | grep HWaddr | awk '{print \$5}'`;
        # We needed to change this to work with non-english OS's
        $mac = `ifconfig $dev | head -n1 | awk '{print \$NF}'`;
        chomp($mac);

        # Generate a new mac address where the last 2 bytes indicate the vlan.
        my @macparts = split(":", $mac);
        $#macparts -= 2; # chomp off last 2 elements
        my ($a,$b) = (int($vlan/256), $vlan%256);
        $a = sprintf("%x", $a);
        $b = sprintf("%x", $b);
        push (@macparts, ($a,$b));
        $mac = join(":", @macparts);

        logsys($f_log_info, "MAC_INFO", "Generated new MAC for $dev: $mac");
        dbquery("UPDATE sensors SET mac = '$mac' WHERE keyname = '$sensor' AND vlanid = '$vlan'");
    }

    # Set mac address
    sys_exec("ifconfig $dev down hw ether $mac");

    # Bring the device up.
    sys_exec("ifconfig $dev up");
}
$g_vlanid = 0;

# Get local gateway.
my $local_gw = getlocalgw();
if ($local_gw eq "false") {
	logsys($f_log_error, "NETWORK_INFO", "No local gateway available");
	exit(1);
}

# Add route to remote ip address via local gateway to avoid routing loops
if (!chkroute($remoteip)) {
    sys_exec("route add -host $remoteip gw $local_gw");
    if ($?) {
	    logsys($f_log_error, "IP_ROUTE", "Failed to add host route");
    	exit(1);
    } else {
	    logsys($f_log_debug, "IP_ROUTE", "Added host route for $remoteip via $local_gw");
    }
} else {
    logsys($f_log_warn, "IP_ROUTE", "Host route for $remoteip already existed");
}
logsys($f_log_info, "NOTIFY", "Connection initial phase - done");
END {
	logsys($f_log_debug, "SCRIPT_END");
    dbdisconnect();
}
