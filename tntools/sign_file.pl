#!/usr/bin/perl

####################################
# Sign a file for the IDS Server   #
# SURFids 3.00                     #
# Changeset 001                    #
# 14-09-2007                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 001 Initial release
#####################

####################
# Variables used
####################
# Loading configuration
do '/etc/surfnetids/surfnetids-tn.conf';

# Retrieving file
$file = $ARGV[0];

# Setting up directories
$udir = "$c_surfidsdir/updates";
$scriptkey = "$c_surfidsdir/scriptkeys/scripts.key";

####################
# Main script
####################
if ($file) {
  `openssl smime -sign -in $udir/$file -text -out $udir/$file.sig -signer $udir/scripts.crt -inkey $scriptkey`;
} else {
  print "No file was given to sign!\n";
}
