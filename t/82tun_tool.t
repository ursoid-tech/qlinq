use strict;
use warnings;
use Test::More;
use t::Util;
my ($stderr, $stdout) = run_prog("python3 t/test_tun_tool.py");
like($stderr, qr/\bOK\b/, "TUN configuration, identities, lifecycle and reconnect");
done_testing;
