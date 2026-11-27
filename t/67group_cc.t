use strict;
use warnings;
use Test::More;
use t::Util;
my ($stderr, $stdout) = run_prog('./t/00util/test_group_cc');
like($stdout, qr/===GROUP RECOVERY CC OK===/,
     'mcbbr group congestion controller tracks BBRv3 bounds and equilibrium')
    or diag($stderr);
done_testing;
