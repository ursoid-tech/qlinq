#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'decomposed transport components' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_components');
    like($stdout, qr/===TRANSPORT COMPONENTS OK===/,
         'component ownership and lookup tests pass') or diag($stderr);
};

subtest 'UDP GSO grouping and partial sends' => sub {
    plan skip_all => 'Linux UDP_SEGMENT syscall coverage' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_udp_gso_prefix');
    like($stdout, qr/UDP GSO grouping and partial-send fault injection passed/,
         'datagrams remain ordered and accepted prefixes are never replayed') or diag($stderr);
};

subtest 'UDP batch receive boundaries' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_udp_receive');
    like($stdout, qr/===UDP RECEIVE OK===/,
         'native and portable receive preserve boundaries, empty packets and truncation') or diag($stderr);
};

subtest 'interface snapshots'  => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_ifmon');
    like($stdout, qr/===IFMON SNAPSHOTS OK===/,
         'interface changes and missing IPv4/IPv6 prefixes retain their semantics') or diag($stderr);
};

done_testing;
