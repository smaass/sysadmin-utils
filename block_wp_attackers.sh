#!/usr/bin/perl

print "Looking for offenders...\n\n";

my %offending_ips;
while (<>) {
	$matches = $_ =~ m/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]).*\[.*]\s"POST\s\/xmlrpc.php.*$/;
	if ($matches) {
		$offending_ips{$1}=1;
	}
}

print "Offending IPs:\n";
foreach $ip (keys %offending_ips) {
	print $ip."\n";
}

my %blocked_ips;
my $output = qx/iptables -L INPUT/;
my @lines = split /\n/, $output;

foreach my $line (@lines) {
	$matches = $line =~ m/DROP.*\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s.*$/;
	if ($matches) {
		$blocked_ips{$1}=1;
	}
}

print "\nIPs already blocked:\n";
foreach $ip (keys %blocked_ips) {
	print $ip."\n";
}

print "\nBlocking IPs not already blocked...\n";
foreach $ip (keys %offending_ips) {
	if (!$blocked_ips{$ip}) {
		print $ip."\n";
		qx/iptables -A INPUT -s $ip -j DROP/;
	}
}

print "\nDone.\n";
