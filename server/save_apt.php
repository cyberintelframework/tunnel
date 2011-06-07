<?php

# Include configuration and connection information.
include 'include/certconf.inc.php';
include 'include/certconn.inc.php';
include 'include/certfunc.inc.php';

$status_offline = 0;
$status_online = 1;
$status_disabled = 3;

$allowed_get = array(
		"strip_html_escape_keyname",
		"int_count"
);

$check = extractvars($_GET, $allowed_get);
debug_input();

# Get remoteip and querystring.
$remoteip = $_SERVER['REMOTE_ADDR'];

# First check if all the variables are present.
$err = 0;

###########
# Keyname #
###########
if (isset($clean['keyname'])) {
	$keyname = $clean['keyname'];
	$pattern = '/^sensor[0-9]+$/';
	if (!preg_match($pattern, $keyname)) {
		echo "ERRNO: 91\n";
		echo "ERROR: Keyname not valid.\n";
		$err = 1;
	}
} else {
	echo "ERRNO: 91\n";
	echo "ERROR: Keyname not valid.\n";
	$err = 1;
	$keyname = "Unknown";
}

##############
# APT output #
##############
if (isset($_GET['apt'])) {
	if (is_array($_GET['apt'])) {
		foreach ($_GET['apt'] as $key => $line) {
			logapt($keyname, $line);
		}
	}
}

###########
# Count   #
###########
if (isset($clean['count'])) {
	$count = $clean['count'];
	logapt($keyname, "Updated APT count: $count");
}

############
# Check if sensor entry exists
############
$sql_sensors = "SELECT id FROM sensor_details WHERE keyname = '$keyname'";
$result_sensors = pg_query($pgconn, $sql_sensors);
$numrows = pg_num_rows($result_sensors);
if ($numrows == 0) {
	echo "ERRNO: 96\n";
	echo "ERROR: Sensor '$keyname' does not exist!\n";
	$err = 1;
} else {
	$sql = "UPDATE sensor_details SET updates = '$count' WHERE keyname = '$keyname'";
	pg_query($pgconn, $sql);
}

# Close the connection with the database.
pg_close($pgconn);
?>
