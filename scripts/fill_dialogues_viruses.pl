#!/usr/bin/perl -w

###########################################
# Fill script for IDS server databas  e   #
# SURFnet IDS                             #
# Version 1.02.01                         #
# 17-05-2006                              #
# Peter Arts                              #
###########################################

#########################################################################################
# Copyright (C) 2005-2006 SURFnet                                                       #
# Author Peter Arts                                                                     #
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

##################
# Modules used
##################
use DBI;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-log.conf';

##################
# Main script
##################

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass);
# Check if the connection to the database did not fail.
if (! $dbh eq "") {
  # Update Dialogues:
  $sql = "SELECT DISTINCT(text) FROM details WHERE type = 1 AND text NOT IN ( SELECT name FROM stats_dialogue )";
  $query = $dbh->prepare($sql);
  $result = $query->execute();

  # Foreach Dialogue which is NOT in stats_dialogue:
  while (@insert = $query->fetchrow_array) {
    # insert:
    $sql = "INSERT INTO stats_dialogue (name) VALUES ('" . $insert[0] . "')";
    $execute_result = $dbh->do($sql);
  }  

  # Update viruses:
  $sql = "SELECT DISTINCT(info) FROM binaries WHERE info NOT IN ( SELECT name FROM stats_virus )";
  $query = $dbh->prepare($sql);
  $result = $query->execute();

  # Foreach virus which is NOT in stats_virus:
  while (@insert = $query->fetchrow_array) {
    # insert:
    $sql = "INSERT INTO stats_virus (name) VALUES ('" . $insert[0] . "')";
    $execute_result = $dbh->do($sql);
  }
}
