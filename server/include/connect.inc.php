<?php

####################################
# SURFnet IDS                      #
# Version 1.04.01                  #
# 20-11-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 1.04.01 Released as 1.04.01
# 1.03.01 Released as part of the 1.03 package
# 1.02.01 Initial release
#####################

$pgconn = pg_connect("host=$c_pgsql_host port=$c_pgsql_port user=$c_pgsql_user password=$c_pgsql_pass dbname=$c_pgsql_dbname");
if (!$pgconn) {
  die('Not connected : ' . pg_last_error($pgconn));
}

?>
