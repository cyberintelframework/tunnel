#!/usr/bin/perl

#########################################
# Status check                          #
# SURFids 2.04                          #
# Changeset 002                         #
# 30-05-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

#############################################
# Changelog:
# 002 Moved script to tools directory
# 001 version 2.00
#############################################

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
%ignore = ("client.conf.dist", 0, "client.conf.temp.dist", 0, "wgetrc.dist", 0, "sensor.conf.dist", 0);

# Looping through the updates directory
@file_ar = `grep -I Version $c_surfidsdir/updates/* | grep -v ".sig" | awk '{print \$1}' | cut -d":" -f1`;
foreach $file (@file_ar) {
  chomp($file);
  $version = `grep -I Version $c_surfidsdir/updates/* | grep "^${file}:" | awk '{print \$3}'`;
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
