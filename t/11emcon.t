#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

my @tests = (
    ['durable activation', './t/00util/test_emcon_activation',
     qr/===EMCON ACTIVATION OK===/],
    ['signed manifest', './t/00util/test_emcon_manifest',
     qr/===EMCON MANIFEST OK===/],
    ['metadata', './t/00util/test_emcon_metadata',
     qr/===EMCON METADATA OK===/],
    ['rateless reconstruction', './t/00util/test_emcon_rateless',
     qr/===EMCON RATELESS OK===/],
    ['receive-only socket', './t/00util/test_emcon_receive_socket',
     qr/===EMCON RECEIVE SOCKET OK===/],
    ['multi-alias session', './t/00util/test_emcon_session',
     qr/===EMCON SESSION OK===/],
);

for my $test (@tests) {
    subtest $test->[0] => sub {
        my ($stderr, $stdout) = run_prog($test->[1]);
        like($stdout, $test->[2], "$test->[0] passes") or diag($stderr);
    };
}

done_testing;
