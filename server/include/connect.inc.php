<?php
####################################
# SURFnet IDS                      #
# Version 1.02.01                  #
# 03-05-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

  $pgconn = pg_connect("host=$pgsql_host port=$pgsql_port user=$pgsql_user password=$pgsql_pass dbname=$pgsql_dbname");
  if (!$pgconn) {
    die('Not connected : ' . pg_last_error($pgconn));
  }
?>
