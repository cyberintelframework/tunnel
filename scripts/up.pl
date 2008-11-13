#!/usr/bin/perl

use warnings;
use strict "vars";

#########################################
# Startup script for IDS server         #
# SURFnet IDS 2.10.00                   #
# Changeset 003                         #
# 15-07-2008                            #
# Jan van Lith & Kees Trippelvitz       #
# Auke Folkerts (changeset 003)         #
#########################################

#####################
# Changelog:
# 003 support multiple vlans per tunnel
# 002 Added logsys stuff
# 001 version 2.10.00 release
#####################


############
# Includes  
############
use vars qw ($c_surfidsdir);
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";


##################
# Modules used
##################
use Time::localtime qw(localtime);
use DBI;


##################
# Global variables
# ################
our $source = "up.pl";	
our $sensor = $ENV{sensor} || die ("no sensor");
our $tap = $ENV{tap} || die ("no tap");
our $remoteip = $ENV{remoteip} || die ("no remoteip");
our $pid = $ENV{pid} || die ("no pid");


###############
# Main script 
###############
logsys(LOG_DEBUG, "SCRIPT_START");


# Check for leftover source based routing rules and delete them.
my $delresult = deliprules($tap);


# Check for leftover source based routing tables and delete if present.
my $flushresult = flushroutes($tap);
if ($flushresult) {
	logsys(LOG_WARN, "SYS_FAIL", "Flushing routes for $tap failed (error code $flushresult)");
}


# bring tap interface up
sys_exec("ifconfig $tap up");
if ($?) {
	logsys(LOG_ERROR, "NETWORK_ERROR", "Failed to bring up device '$tap' (error code $?)");
	exit(1);
}


# Get local gateway.
my $local_gw = getlocalgw();
if ($local_gw eq "false") {
	logsys(LOG_ERROR, "NETWORK_ERROR", "No local gateway available");
	exit(1);
} else {
	logsys(LOG_DEBUG, "NOTIFY", "Local gateway: $local_gw");
}


# Add route to remote ip address via local gateway to avoid routing loops
sys_exec("route add -host $remoteip gw $local_gw");
if ($?) {
	logsys(LOG_ERROR, "NETWORK_ERROR", "Failed to add host route (error code  $?)");
	exit(1);
} else {
	logsys(LOG_DEBUG, "NOTIFY", "Added host route for $remoteip via $local_gw");
}


END {
	logsys(LOG_DEBUG, "SCRIPT_END");
}
