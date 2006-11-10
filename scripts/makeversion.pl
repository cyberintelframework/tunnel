#!/usr/bin/perl -w

#########################################
# Status check                          #
# SURFnet IDS                           #
# Version 1.04.01                       #
# 07-11-2006                            #
# Kees Trippelvitz                      #
#########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
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

#############################################
# Changelog:
# 1.04.01 Initial release. Converted from makeversion.sh.
#############################################

##################
# Modules used
##################
use Time::localtime;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';

##################
# Main script
##################

`rm -f $surfidsdir/updates/server_version.txt`;

# Setting up ignored files
%ignore = ("client.conf.dist", 0, "wgetrc.dist", 0);

# Opening server_version.txt for writing
open(VERS, "> $surfidsdir/updates/server_version.txt");

# Looping through the updates directory
@file_ar = `grep -I Version $surfidsdir/updates/* | grep -v ".sig" | awk '{print \$1}' | cut -d":" -f1`;
foreach $file (@file_ar) {
  chomp($file);
  $version = `grep -I Version $surfidsdir/updates/* | grep "^${file}:" | awk '{print \$3}'`;
  chomp($version);
  $file = `echo $file | awk -F / '{print \$NF}'`;
  chomp($file);
  if (!exists $ignore{$file}) {
    # Signing file
    `$surfidsdir/scripts/sign_file.pl $file`;
    # Updating the server_version.txt
    print "$file:$version\n";
    print VERS "${file}:${version}\n";
  }
}
close(VERS);

print "Creation of $surfidsdir/updates/server_version.txt done!\n";

