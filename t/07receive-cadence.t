#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
for my $case (
    ['test_rx_cadence', 'RX CADENCE SCHEDULE', 'bounded receive wait and bypass/error semantics'],
    ['test_rx_cadence_backlog', 'RX CADENCE BACKLOG', 'actual UDP/GRO backlog, fairness and socket lifetime'],
    ['test_rx_cadence_real', 'RX CADENCE REAL', 'queued/callback delivery, recovery and active peer close']) {
    my ($stderr, $stdout) = run_prog("./t/00util/$case->[0]");
    like($stdout, qr/===\Q$case->[1]\E OK===/, $case->[2]) or diag($stderr);
}
done_testing;
