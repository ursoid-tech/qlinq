use strict;
use warnings;
use Test::More;
use t::Util;

subtest "multipath transport test" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_multipath");
	diag "STDERR:\n$stderr";
	diag "STDOUT:\n$stdout";
	like $stdout, qr/===MULTIPATH OK===/, "multipath connection, 4 paths validation, data flow, and qlog debug socket successful";
};

subtest "reliable failover with the QLINQ scheduler" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_multipath_failover");
	diag "STDERR:\n$stderr" if $stderr;
	like $stdout, qr/===MULTIPATH FAILOVER OK===/,
		"continuous writes recover across primary, secondary and bidirectional outages";
};

subtest "feedback on remote paths sharing one local socket" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_multipath_feedback");
	diag "STDERR:\n$stderr" if $stderr;
	like $stdout, qr/===MULTIPATH FEEDBACK OK===/,
		"both feedback queues drain and deliver without a permanently due timer";
};

subtest "coded publication retains native path measurement identity" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_multipath_publication");
	diag "STDERR:\n$stderr" if $stderr;
	like $stdout, qr/===MULTIPATH PUBLICATION OK===/,
		"a healthy alternate does not inherit another remote path's loss or delay";
};

done_testing();
