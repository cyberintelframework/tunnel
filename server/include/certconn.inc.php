<?php

####################################
# SURFids 2.00.03                  #
# Changeset 001                    #
# 22-05-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 001 version 2.00
#####################

$pgconn = pg_connect("host=$c_pgsql_host port=$c_pgsql_port user=$c_pgsql_user password=$c_pgsql_pass dbname=$c_pgsql_dbname");
if (!$pgconn) {
  die('Not connected : ' . pg_last_error($pgconn));
}

?>
