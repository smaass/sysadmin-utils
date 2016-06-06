#!/usr/bin/perl
use POSIX qw/strftime/;

my $datetime = strftime('%Y-%m-%d %H:%M:%S', localtime);
print "[$datetime] Looking for offenders...\n";

my %offending_ips;
while (<>) {
        $matches = $_ =~ m/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*\[.*]\s"POST\s\/xmlrpc.php.*$/;
        if ($matches) {
                $offending_ips{$1}=1;
        }
}

my %blocked_ips;
my @output = `/sbin/iptables -L INPUT -n`;

foreach my $line (@output) {
        $matches = $line =~ m/DROP.*\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s.*$/;
        if ($matches) {
                $blocked_ips{$1}=1;
        }
}

my @to_block;
foreach $ip (keys %offending_ips) {
        if (!$blocked_ips{$ip}) {
                push @to_block , $ip;
        }
}

if (scalar @to_block > 0) {
        my $datetime = strftime('%Y-%m-%d %H:%M:%S', localtime);
        print "[$datetime] Blocking IPs: @to_block\n";
        for $ip (@to_block) {
                `/sbin/iptables -A INPUT -s $ip -j DROP`;
		`/usr/sbin/invoke-rc.d iptables-persistent save`;
        }
}
