use strict;
use warnings;
use Test::More;
use t::Util;

subtest "crypto backend selection and packet interoperability" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_crypto_backend");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===CRYPTO BACKENDS OK===/,
	  "default, explicit, invalid and Fusion settings preserve packet protection";
};

subtest "mutual TLS policy" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_tls");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===TLS OK===/,
	  "trusted peer authenticates and an untrusted certificate is rejected";
};

subtest "opt-in Fusion mutual TLS policy" => sub {
	local $ENV{QLINQ_CRYPTO_BACKEND} = "fusion";
	my ($stderr, $stdout) = run_prog("./t/00util/test_tls");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===TLS OK===/,
	  "opt-in backend preserves trusted and untrusted certificate behavior";
};

done_testing();
