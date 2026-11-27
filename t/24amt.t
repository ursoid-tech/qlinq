#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
plan skip_all => 'Linux AMT polling host tests' unless $^O eq 'linux';
for my $case (['./t/00util/test_amt_relay', 'opaque packet transparency and PMTU'],
              ['./t/00util/test_amt_transport --amt', 'two AMT receivers'],
              ['./t/00util/test_amt_transport --amt-mixed', 'native and AMT receivers'],
              ['./t/00util/test_amt_transport --amt-unavailable', 'AMT timeout keeps unicast delivery']) {
    subtest $case->[1] => sub {
        my ($stderr, $stdout) = run_prog($case->[0]);
        like($stdout, qr/===.* OK===/, 'delivery succeeds') or diag($stderr);
    };
}
subtest 'network mode CLI delivery' => sub {
    my ($stderr, $stdout) = run_prog('python3 t/test_network_modes.py');
    like($stdout, qr/===NETWORK MODE CLI OK===/, 'P2P, two multicast receivers and AMT fallback preserve bytes') or diag($stderr);
};
subtest 'mode validation' => sub {
    my $help = `./qlinq-app --help`;
    like($help, qr/--network-mode p2p\|multicast-fanout\|amt-relay/, 'documents three modes');
    for my $args ('--network-mode bad', '--network-mode amt-relay',
                  '--network-mode amt-relay --relay-interface lo --input README.md',
                  '--network-mode amt-relay --relay-interface lo --cert x --key y',
                  '--network-mode amt-relay --relay-interface lo --relay-clients 1025',
                  '--network-mode amt-relay --relay-interface lo --relay-mtu 575',
                  '--network-mode amt-relay --relay-interface lo --bind bad',
                  '--network-mode multicast-fanout --listen 19999',
                  '--network-mode p2p --group 232.42.42.1',
                  '--network-mode multicast-fanout --peer 127.0.0.1 --amt-port 2268') {
        my $output = `./qlinq-app $args 2>&1`;
        isnt($?, 0, "rejects $args");
        like($output, qr/invalid command line/, 'rejects before opening sockets');
    }
};
done_testing;
