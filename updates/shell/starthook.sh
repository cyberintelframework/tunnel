#!/bin/sh

#########################################
# Userdefined commands for the sensor   #
# SURFnet IDS                           #
# Version 1.02.01                       #
# 29-05-2006                            #
#########################################

`iptables -F`
`iptables -A OUTPUT -p TCP -m physdev --physdev-out tap0 --dport 1194 -j DROP`

