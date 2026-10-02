use strict;
use warnings;
use Test::More;
use t::Util;
my ($stderr, $stdout) = run_prog("./t/00util/test_tun_json");
like($stdout, qr/=== TUN JSON OK ===/, "bounded native JSON parser rejects malformed input");
done_testing;
