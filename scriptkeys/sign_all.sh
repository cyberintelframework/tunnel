#!/bin/sh

#########################################
# Sign all updates for the IDS Server   #
# SURFnet IDS                           #
# Version 1.02.01                       #
# 15-02-2006                            #
# Kees Trippelvitz                      #
#########################################

####################
# Variables used
####################
udir="/home/surfids/trunk/updates"
basedir="/home/surfids/trunk/scriptkeys"

####################
# Main script
####################
rm $udir/*.sig
$basedir/makeversion.sh
$basedir/sign_file.sh $udir $basedir client.conf
$basedir/sign_file.sh $udir $basedir idsmenu.pl
$basedir/sign_file.sh $udir $basedir bridgestart.pl
$basedir/sign_file.sh $udir $basedir startclient.pl
$basedir/sign_file.sh $udir $basedir stopclient.pl
$basedir/sign_file.sh $udir $basedir update.pl
$basedir/sign_file.sh $udir $basedir update_remove.pl
$basedir/sign_file.sh $udir $basedir wgetrc
$basedir/sign_file.sh $udir $basedir scripts.crt
$basedir/sign_file.sh $udir $basedir perl.conf
$basedir/sign_file.sh $udir $basedir network_config.pl
$basedir/sign_file.sh $udir $basedir functions.inc.pl

