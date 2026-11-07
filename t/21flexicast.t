#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
for my $mode ('--base', '--native', '--native6', '--join-fallback',
              '--ack-fallback', '--pacing', '--control-flood',
              '--membership', '--membership6', '--unsubscribe', '--unsubscribe6') {
    subtest "Flexicast $mode" => sub {
        my ($stderr, $stdout) = run_prog("./t/00util/test_flexicast_transport $mode");
        like($stdout, qr/===FLEXICAST .* OK===/, 'group transport and lifecycle pass')
            or diag($stderr);
    };
}
done_testing;
