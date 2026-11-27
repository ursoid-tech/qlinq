#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use t::Util;
for my $mode ('--base', '--native', '--native6', '--native6-fallback',
              '--mixed-retry', '--join-fallback',
              '--ack-fallback', '--pacing', '--control-flood',
              '--membership', '--membership6', '--unsubscribe', '--unsubscribe6',
              '--untracked') {
    subtest "Flexicast $mode" => sub {
        my ($stderr, $stdout) = run_prog("./t/00util/test_flexicast_transport $mode");
        if ($mode eq '--native6' && $stdout =~ /^SKIP (.+)$/m) {
            plan skip_all => $1;
        }
        like($stdout, qr/===FLEXICAST .* OK===/, 'group transport and lifecycle pass')
            or diag($stderr);
    };
}
done_testing;
