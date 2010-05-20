#!/usr/bin/perl

####################################
# SVN dir cleanup script           #
# SURFids 3.00                     #
# Changeset 001                    #
# 29-10-2007                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

# Removes all .svn directories in the given directory
# Usage: ./rmsvn.pl /opt/surfnetids/

#####################
# Changelog:
# 001 Initial version
#####################

##################
# Modules used
##################

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Main script
##################
if (!$ARGV[0]) {
  print "No directory to clean is given!\n";
  print "Usage: ./rmsvn.pl /opt/surfnetids/\n";
  exit 1;
} else {
  $startdir = $ARGV[0];
  chomp($startdir);
}

sub rmsvn {
  my ($dir, $file, $newdir);
  $dir = $_[0];
  opendir(DH, $dir);
  foreach (readdir(DH)) {
    $file = $_;
    if ($file !~ /^(\.|\.\.)$/) {
      if ($file ne "svnroot") {
        if (-d "$dir$file") {
          if ($file =~ /^\.svn$/) {
            `rm -r $dir$file/`;
          } else {
            $newdir = "$dir$file/";
            &rmsvn($newdir);
          }
        }
      }
    }
  }
  close(DH);
}

rmsvn($startdir);
