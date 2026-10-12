use strict;
use warnings;
use Test::More;
use t::Util;

subtest "generic data pipe and TUN daemon test" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_tund");
	like $stdout, qr/===TUND OK===/, "bidirectional TUN packets routed and multiplexed successfully over QUIC loopback";
};

subtest "TUN local framing rejects oversized and short mock packets" => sub {
	my ($stderr, $stdout) = run_prog("python3 t/00util/test_tund_framing.py");
	like $stdout, qr/===TUND FRAMING OK===/, "bounded frames reconnect and valid packets retain their framing";
};

done_testing();
