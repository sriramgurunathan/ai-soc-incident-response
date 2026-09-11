#!/usr/bin/env perl
# ====================================================================
# ApexShield Network Reconnaissance & Port Sweep Simulator (Perl)
# ====================================================================
use strict;
use warnings;
use IO::Socket::INET;

my $target_host = $ARGV[0] || '127.0.0.1';
my @target_ports = (21, 22, 23, 25, 80, 443, 3306, 5432, 8000, 8080);

print "
[ApexShield DFIR] Initializing Perl Port Sweep Simulation against $target_host...
";
print "--------------------------------------------------------------------------
";

foreach my $port (@target_ports) {
    my $socket = IO::Socket::INET->new(
        PeerAddr => $target_host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 0.2
    );

    if ($socket) {
        print "[+] Port $port/TCP : OPEN
";
        close($socket);
    } else {
        print "[-] Port $port/TCP : CLOSED / FILTERED
";
    }
}

print "--------------------------------------------------------------------------
";
print "[+] Reconnaissance simulation cycle completed.

";
