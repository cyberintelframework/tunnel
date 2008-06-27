#!/usr/bin/perl

#########################################
# Script to mount the sensor rw or ro   #
# SURFids 2.00.03                       #
# Changeset 001                         #
# 22-05-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

###################
# Changelog:
# 001 Initial release
###################

$basedir = "/cdrom/scripts/";
require "$basedir/functions.inc.pl";

$state = $ARGV[0];
chomp($state);

if ("$state" ne "") {
  remount($state);
} else {
  print "No state given!\n";
}
