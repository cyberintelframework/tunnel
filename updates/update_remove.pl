#!/usr/bin/perl -w

###################################
# Update script for update.pl
# SURFnet IDS
# Version 1.02.03
# 04-09-2006
# Jan van Lith & Kees Trippelvitz
###################################

# This script is started by update.

################
# Variables    #
################
$basedir = "/cdrom/scripts";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";
$updatenew = $ARGV[0];

################
# Start script #
################
# Removing update.
`rm -f $basedir/update`;
printmsg("Removing update script:", $?);

# Getting new version of update.
`sed 's/\\r//' $updatenew > $basedir/update.pl`;
printmsg("Updating update.pl:", $?);

`rm -f $updatenew`;
printmsg("Cleaning up temporary files:", $?);

print "${y}Updates complete!\n${n}";
