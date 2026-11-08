use strict;
use warnings;
use Test::More;
use t::Util;
my ($err, $out) = run_prog('./t/00util/test_publication_limits');
like($out, qr/===PUBLICATION LIMITS OK===/, 'negotiated FEC limits and grouping') or diag($err);
($err, $out) = run_prog('./t/00util/test_publication_deadlines');
like($out, qr/===PUBLICATION DEADLINES OK===/, 'expired groups retire and deadlines stay with their publications') or diag($err);
done_testing;
