<?php
####################################
# SURFnet IDS                      #
# Version 1.03.01                  #
# 11-10-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 1.03.01 Released as part of the 1.03 package
# 1.02.01 Initial release
#####################

$pgconn = pg_connect("host=$pgsql_host port=$pgsql_port user=$pgsql_user password=$pgsql_pass dbname=$pgsql_dbname");
if (!$pgconn) {
  die('Not connected : ' . pg_last_error($pgconn));
}

?>
