use strict;
use warnings;
use Test::More;
use t::Util;
my ($name_stderr, $name_stdout) = run_prog("./t/00util/test_tun_names");
like($name_stdout, qr/=== TUN INTERFACE NAMES OK ===/, "TUN path names resolve devices, loopback and fallback");
my ($stderr, $stdout) = run_prog("python3 t/test_tun_metrics.py");
like($stderr, qr/\bOK\b/, "TUN Prometheus metrics, freshness and atomic textfiles");
done_testing;
