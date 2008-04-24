#!/usr/bin/perl

require "/etc/surfnetids/surfnetids-tn.conf";
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
require "$c_surfidsdir/genkeys/vars.conf";

# Client specific variables.
$KEY_NAME = $ARGV[0];
$ENV{"KEY_COMMONNAME"} = $KEY_NAME;
$ENV{"D"} = $c_surfidsdir;
$ENV{"KEY_CONFIG"} = "$key_config";
$ENV{"KEY_DIR"} = $key_dir;
$ENV{"KEY_SIZE"} = "$key_size";
$ENV{"KEY_COUNTRY"} = "$key_country";
$ENV{"KEY_PROVINCE"} = "$key_province";
$ENV{"KEY_CITY"} = "$key_city";
$ENV{"KEY_ORG"} = "$key_org";
$ENV{"KEY_EMAIL"} = "$key_email";
$ENV{"KEY_UNITNAME"} = "$key_unitname";
$ENV{"KEY_CERTTYPE"} = "$key_certtype";

# Run the build-key command.
`$genkeys/build-key $clientkeys/$KEY_NAME`;
