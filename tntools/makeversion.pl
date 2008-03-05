#!/usr/bin/perl

#########################################
# Status check                          #
# SURFnet IDS                           #
# Version 2.00.02                       #
# 27-09-2007                            #
# Jan van Lith & Kees Trippelvitz       #
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
# 2.00.02 Moved script to tools directory
# 2.00.01 version 2.00
# 1.04.03 Fixed typo in the last print statement
# 1.04.02 Removed the server_version.txt stuff
# 1.04.01 Initial release. Converted from makeversion.sh.
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
