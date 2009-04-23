#!/usr/bin/perl

####################################
# Status check                     #
# SURFids 3.00                     #
# Changeset 002                    #
# 18-06-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 002 Added client.conf to ignore list
# 001 Initial release
#####################

##################
# Modules used
##################
use Time::localtime qw(localtime);

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';

##################
# Main script
##################

# Setting up ignored files
%ignore = ("client.conf.dist", "client.conf.temp.dist", "wgetrc.dist", "sensor.conf.dist", "client.conf");

# Looping through the updates directory
@file_ar = `grep -I Changeset $c_surfidsdir/updates/* | grep -v ".sig" | awk '{print \$1}' | cut -d":" -f1`;
foreach $file (@file_ar) {
  chomp($file);
  $version = `grep -I Changeset $c_surfidsdir/updates/* | grep "^${file}:" | awk '{print \$3}' | head -n1`;
  chomp($version);
  $file = `echo $file | awk -F / '{print \$NF}'`;
  chomp($file);
  if (!exists $ignore{$file}) {
    # Signing file
    `$c_surfidsdir/tntools/sign_file.pl $file`;
    print "$file:$version\n";
  }
}

print "Signing scripts done!\n";
