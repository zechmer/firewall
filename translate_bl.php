<?php

#!/usr/bin/php

# Translate given ip blocklist into iptables format
# so that incomming and outgoing connections are blocked

# Get filename as parameter from the command line
$filename=$argv[1];
print "Reading $filename";
#$filename="blocklist1";
$tmp="_tmp";
$outfile=$filename . $tmp;
$handle = fopen($filename, "r");
$writeout = fopen($outfile,"w");

$newline="\n";
if ($handle) {
    while (($line = fgets($handle)) !== false) {

	# This should be a comment...
	$ip1=substr_replace( $line, "# ", 0, 0);

	#  Just insert a newline and the iptables rule
	$replacement = $newline."iptables -A INPUT -m iprange --src-range ";

	$ip2=str_replace( ":", $replacement, $ip1);
	# Insert DROP jump at the end
    	$ip3=substr_replace( $ip2, " -j DROP".$newline, strlen($ip2)-1, 0);
#	print $ip3;
	fwrite($writeout,$ip3);

	# now take this rule and replace INPUT by OUTPUT and src by dst...
	$ip4=str_replace( "INPUT", "OUTPUT", $ip3);
	$ip5=str_replace( "src",   "dst",    $ip4);
	fwrite($writeout,$ip5);

    }
} else {
	print "Error reading file";
}

fclose($handle);
fclose($writeout);
