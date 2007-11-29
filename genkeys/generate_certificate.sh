#!/bin/sh

# Load the generic certificate variables.
. /opt/surfnetids/2.10/tunnel/trunk/genkeys/vars.conf

# Client specific variables.
KEY_NAME=$1
export KEY_COMMONNAME=$KEY_NAME

# Run the build-key command.
sh $genkeys/build-key $clientkeys/$KEY_NAME
