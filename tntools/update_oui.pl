#!/usr/bin/perl

####################################
# Update script for oui.txt        #
# SURFids 2.10                     #
# Changeset 002                    #
# 22-05-2007                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#############################################
# Changelog:
# 002 Added QEMU and Bochs OUI
# 001 Initial release.
#############################################

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';

`wget -O $c_surfidsdir/scripts/oui_new.txt http://standards.ieee.org/regauth/oui/oui.txt`;
`grep "\(hex\)" $c_surfidsdir/scripts/oui_new.txt | awk '{gsub(/-/,":",\$1);\$2="";print}' > $c_surfidsdir/scripts/oui.txt`;
`rm $c_surfidsdir/scripts/oui_new.txt`;
`echo "52:54:00  QEMU" >> $c_surfidsdir/scripts/oui.txt`;
`echo "B0:C4:20  Bochs" >> $c_surfidsdir/scripts/oui.txt`;
print "Updating oui database done!\n";
