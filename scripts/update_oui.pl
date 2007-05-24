#!/usr/bin/perl -w

#########################################
# Update script for oui.txt             #
# SURFnet IDS                           #
# Version 1.04.01                       #
# 23-05-2007                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

#############################################
# Changelog:
# 1.04.01 Initial release.
#############################################

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';

`wget -O $c_surfidsdir/scripts/oui_new.txt http://standards.ieee.org/regauth/oui/oui.txt`;
`grep "\(hex\)" $c_surfidsdir/scripts/oui_new.txt | awk '{gsub(/-/,":",\$1);\$2="";print}' > $c_surfidsdir/scripts/oui.txt`;
`rm $c_surfidsdir/scripts/oui_new.txt`;
print "Updating oui database done!\n";
