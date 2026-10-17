#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'egress fault recovery' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_egress_errors');
    like($stdout, qr/===EGRESS ERRORS OK===/, 'hard errors do not strand unrelated datagrams') or diag($stderr);
};
subtest 'Quicly Flexicast unit suite' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_quicly_flexicast');
    unlike($stdout, qr/^\s*not ok/m, 'all Quicly assertions pass') or diag($stderr);
    like($stdout, qr/^1\.\.\d+/m, 'Quicly completed TAP suite');
};
subtest 'Flexicast regression matrix' => sub {
    for my $cc ('', 'adaptive') {
        for my $mode ('pacing 1', 'pacing 5', 'pacing 12', 'pacer-high 1', 'pacer-high 2', 'pacer-maximum 1', 'pacer-aliases 2', 'pacer-rtt 2', 'pacer-native-fallback 2', 'ecn 2', 'native-ecn 2', 'blocked-fanout 5', 'aliases 5', 'rekey 2', 'partial-rekey 5', 'egress-rekey 2', 'control-queue 2',
                      'controls 2', 'rateless-ready-baseline 2', 'rateless-recovery-fairness 1', 'rateless-recovery-dedup 1', 'limits 2', 'fixed 2', 'rateless 2', 'fixed-cache 2', 'rateless-cache 2', 'video-rateless 1', 'native 2', 'native-wildcard 2', 'native-ingress 1') {
            my ($stderr, $stdout) = run_prog("./t/00util/test_flexicast_regressions $mode $cc");
            like($stdout, qr/===FLEXICAST REGRESSIONS OK===/, "$mode $cc") or diag($stderr);
        }
    }
};
done_testing;
