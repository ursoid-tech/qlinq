#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
plan skip_all => 'Linux AMT polling host tests' unless $^O eq 'linux';
for my $case (['./t/00util/test_amt_relay', 'opaque packet transparency, AMTQ, mTLS, dual-stack and PMTU'],
              ['./t/00util/test_amt_transport --amt', 'two AMT receivers'],
              ['./t/00util/test_amt_transport --amt-mixed', 'native and AMT receivers'],
              ['./t/00util/test_amt_transport --amt-unavailable', 'AMT timeout keeps unicast delivery'],
              ['./t/00util/test_amt_transport --amtq', 'two verified AMTQ datagram receivers'],
              ['./t/00util/test_amt_transport --amtq-reliable', 'two verified AMTQ reliable block receivers'],
              ['./t/00util/test_amt_transport --amtq-mixed', 'native and AMTQ receivers'],
              ['./t/00util/test_amt_transport --auto-amt', 'AUTO native failure selects AMT'],
              ['./t/00util/test_amt_transport --auto-amtq', 'AUTO native and AMT failure selects AMTQ']) {
    subtest $case->[1] => sub {
        my ($stderr, $stdout) = run_prog($case->[0]);
        like($stdout, qr/===.* OK===/, 'delivery succeeds') or diag($stderr);
    };
}
subtest 'network mode CLI delivery' => sub {
    my ($stderr, $stdout) = run_prog('python3 t/test_network_modes.py');
    like($stdout, qr/===NETWORK MODE CLI OK===/, 'P2P, multicast, AMT and AMTQ CLI modes preserve bytes') or diag($stderr);
};
subtest 'mode validation' => sub {
    my $help = `./qlinq-app --help`;
    like($help, qr/--network-mode p2p\|multicast-fanout\|amt-relay\|amtq-relay/, 'documents network modes');
    for my $args ('--network-mode bad', '--network-mode amt-relay',
                  '--network-mode amtq-relay --relay-interface lo',
                  '--network-mode amt-relay --relay-interface lo --input README.md',
                  '--network-mode amt-relay --relay-interface lo --cert x --key y',
                  '--network-mode amt-relay --relay-interface lo --listen 2268 --amtq-port 2268 --cert x --key y',
                  '--network-mode amtq-relay --relay-interface lo --linux-gateway-family 4 --cert x --key y',
                  '--network-mode amt-relay --relay-interface lo --relay-clients 1025',
                  '--network-mode amt-relay --relay-interface lo --relay-sources 65536',
                  '--network-mode amt-relay --relay-interface lo --relay-mtu 575',
                  '--network-mode amt-relay --relay-interface lo --bind bad',
                  '--network-mode multicast-fanout --listen 19999',
                  '--network-mode p2p --group 232.42.42.1',
                  '--network-mode multicast-fanout --peer 127.0.0.1 --amt-port 2268',
                  '--network-mode multicast-fanout --peer 127.0.0.1 --amt-relay 127.0.0.1 --amtq-reliable') {
        my $output = `./qlinq-app $args 2>&1`;
        isnt($?, 0, "rejects $args");
        like($output, qr/invalid command line/, 'rejects before opening sockets');
    }
};
done_testing;
