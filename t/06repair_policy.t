use strict;
use warnings;
use Test::More;
use t::Util;
my ($stderr, $stdout) = run_prog('./t/00util/test_repair_policy');
like($stdout, qr/===REPAIR POLICY OK===/, 'repair policy validation, inheritance, ceilings and immutable expiry') or diag($stderr);
done_testing;
