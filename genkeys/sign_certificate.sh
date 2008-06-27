#!/bin/sh

# Load the generic certificate variables.
. /opt/surfnetids/genkeys/vars.conf

# Client specific variables.
KEY_NAME=$1
export KEY_COMMONNAME=$KEY_NAME

# Run the signing request command.
sh $genkeys/sign-req $clientkeys/$KEY_NAME
