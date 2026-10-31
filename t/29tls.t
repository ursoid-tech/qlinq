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

subtest "TLS group policy and local capability" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_tls_groups");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===TLS GROUPS OK===/,
	  "group lists, provider failures, unavailable builds and endpoint isolation";
};

subtest "actual TLS groups and application barrier" => sub {
	plan skip_all => "link-wrapper fixture requires Linux" unless $^O eq "linux";
	my ($stderr, $stdout) = run_prog("./t/00util/test_tls_barrier");
	diag "STDERR:\n$stderr" if $stderr ne "";
	if ($stdout =~ /TLS BARRIER SKIP/) {
		plan skip_all => "hybrid unavailable in this build/provider configuration";
	} else {
		like $stdout, qr/===TLS BARRIER OK===/,
		  "verified negotiations and receive-callback barrier enforcement";
	}
};

subtest "Fusion TLS group and barrier compatibility" => sub {
	plan skip_all => "link-wrapper fixture requires Linux" unless $^O eq "linux";
	local $ENV{QLINQ_CRYPTO_BACKEND} = "fusion";
	my ($stderr, $stdout) = run_prog("./t/00util/test_tls_barrier");
	diag "STDERR:\n$stderr" if $stderr ne "";
	if ($stdout =~ /TLS BARRIER SKIP/) {
		plan skip_all => "hybrid unavailable in this build/provider configuration";
	} else {
		like $stdout, qr/===TLS BARRIER OK===/,
		  "explicit backend selection preserves policy and application barrier";
	}
};

subtest "recorded Picotls patch preparation" => sub {
	my ($stderr, $stdout) = run_prog("python3 t/test_picotls_patch.py");
	like $stdout, qr/===PICOTLS PATCH OK===/,
	  "pristine, patched and unexpected-edit states are handled safely";
};

subtest "PQC CLI, managed profiles and network faults" => sub {
	my ($stderr, $stdout) = run_prog("python3 t/test_pqc_cli.py");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===PQC CLI OK===/,
	  "verified transfers, network faults, profile compatibility, restart and reload";
};

done_testing();
