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
$basedir/sign_file.sh $udir $basedir idsmenu
$basedir/sign_file.sh $udir $basedir bridgestart
$basedir/sign_file.sh $udir $basedir startclient
$basedir/sign_file.sh $udir $basedir stopclient
$basedir/sign_file.sh $udir $basedir update
$basedir/sign_file.sh $udir $basedir removeupdate
$basedir/sign_file.sh $udir $basedir wgetrc
$basedir/sign_file.sh $udir $basedir scripts.crt
$basedir/sign_file.sh $udir $basedir sensor.conf
$basedir/sign_file.sh $udir $basedir confignetwork
$basedir/sign_file.sh $udir $basedir functions.inc.pl

