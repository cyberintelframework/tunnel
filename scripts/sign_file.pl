#!/usr/bin/perl -w

####################################
# Sign a file for the IDS Server   #
# SURFnet IDS                      #
# Version 1.04.01                  #
# 15-02-2006                       #
# Kees Trippelvitz                 #
####################################

#####################
# Changelog:
# 1.04.01 Rereleased as perl script
# 1.02.01 Initial release
#####################

####################
# Variables used
####################
# Loading configuration
do '/etc/surfnetids/surfnetids-tn.conf';

# Retrieving file
$file = $ARGV[0];

# Setting up directories
$udir = "$surfidsdir/updates";
$scriptkey = "$surfidsdir/scriptkeys/scripts.key";

####################
# Main script
####################
if ($file) {
  `openssl smime -sign -in $udir/$file -text -out $udir/$file.sig -signer $udir/scripts.crt -inkey $scriptkey`;
} else {
  print "No file was given to sign!\n";
}
