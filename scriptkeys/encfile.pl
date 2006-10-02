#!/usr/bin/perl -w

###################################
# SQL script for IDS server       #
# SURFnet IDS                     #
# Version 1.02.02                 #
# 29-02-2006                      #
# Jan van Lith & Kees Trippelvitz #
# Modified by Peter Arts          #
###################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
# Modified by Peter Arts                                                                #
#                                                                                       #
# This program is free software; you can redistribute it and/or                         #
# modify it under the terms of the GNU General Public License                           #
# as published by the Free Software Foundation; either version 2                        #
# of the License, or (at your option) any later version.                                #
#                                                                                       #
# This program is distributed in the hope that it will be useful,                       #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                        #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                         #
# GNU General Public License for more details.                                          #
#                                                                                       #
# You should have received a copy of the GNU General Public License                     #
# along with this program; if not, write to the Free Software                           #
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.       #
#                                                                                       #
# Contact ids@surfnet.nl                                                                #
#########################################################################################

#####################
# Changelog:
# 1.02.02 Added ARP monitoring support
# 1.02.01 Initial release
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime;

##################
# Variables used
##################
# Get the organisation
$org = $ARGV[0];
chomp($org);

do '/etc/surfnetids/surfnetids-tn.conf';

##################
# Functions
##################
sub prompt {
  local($promptstring) = @_;
  print $promptstring;

  $| = 1;               # force a flush after our print
  $_ = <STDIN>;         # get the input from STDIN (presumably the keyboard)

  chomp;
  return $_;
}

##################
# Main script
##################

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
      or die $DBI::errstr;

$sth = $dbh->prepare("SELECT id FROM organisations WHERE organisation = '$org'");
$execute_result = $sth->execute();

if ($execute_result == 0) {
  $return = "";
  while ($return ne "n" && $return ne "y") {
    $return = &prompt("The organisation is not present. Would you like to create it? [y/n]: ");
  }
} else {
  @row = $sth->fetchrow_array;
  $orgid = $row[0];
  $script = `md5sum /home/surfids/trunk/scriptkeys/scripts.key | awk '{print \$1}'`;
  chomp($script);
  $newmd5 = "$org" . "$script";
  $newmd5 = `echo $newmd5 | md5sum | awk '{print \$1}'`;
  chomp($newmd5);
  print "MD5: $newmd5\n";
}
