#!/bin/sh

####################################
# Sign a file for the IDS Server   #
# SURFnet IDS                      #
# Version 1.03.01                  #
# 17-10-2006                       #
# Kees Trippelvitz                 #
####################################

####################
# Variables used
####################
udir="$1"
scriptkeys="$2"
file="$3"

####################
# Main script
####################
openssl smime -sign -in $udir/$file -text -out $udir/$file.sig -signer $udir/scripts.crt -inkey $scriptkeys/scripts.key
