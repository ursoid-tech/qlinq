use strict;
use warnings;
use Test::More;
use File::Copy qw(copy);
use File::Temp qw(tempdir);
use t::Util;

# Exercise the real parallel Makefile rules without changing the suite's own
# credentials while other tests may be using them.
my $directory = tempdir(CLEANUP => 1);
mkdir "$directory/scripts" or die "mkdir: $!";
copy('Makefile', "$directory/Makefile") or die "copy Makefile: $!";
copy('scripts/gencert.sh', "$directory/scripts/gencert.sh")
    or die "copy gencert: $!";
my $make = "make --no-print-directory -C '$directory' -j4 gencerts";
my $assets = "$directory/t/assets";

sub contents {
    open my $file, '<', $_[0] or die "open $_[0]: $!";
    local $/;
    return <$file>;
}

run_prog($make);
my @names = qw(server verified verified-v6 untrusted);
my %original = map { $_ => contents("$assets/$_.crt") } @names;
ok(!grep({ !-s "$assets/$_.key" } @names), 'missing certificate/key pairs are generated');
run_prog($make);
is_deeply([map { contents("$assets/$_.crt") } @names],
          [map { $original{$_} } @names], 'valid certificates are reused');

# A certificate with only one day left must renew before a long suite starts.
run_prog("openssl req -x509 -key '$assets/verified.key' -days 1 " .
         "-out '$assets/verified.crt' -subj /CN=localhost");
my $expiring = contents("$assets/verified.crt");
run_prog($make);
isnt(contents("$assets/verified.crt"), $expiring, 'expiring certificate is renewed');
run_prog("openssl verify -CAfile '$assets/verified.crt' '$assets/verified.crt'");
pass('renewed certificate verifies');
is(contents("$assets/unsafe.key"), contents("$assets/verified.key"),
   'unsafe-key fixture follows the renewed identity');
is((stat("$assets/unsafe.key"))[2] & 0777, 0644,
   'unsafe-key fixture retains its deliberately unsafe permissions');
is_deeply([map { contents("$assets/$_.crt") } qw(server verified-v6 untrusted)],
          [map { $original{$_} } qw(server verified-v6 untrusted)],
          'renewal leaves other valid identities unchanged');

unlink "$assets/verified-v6.key" or die "unlink: $!";
run_prog($make);
isnt(contents("$assets/verified-v6.crt"), $original{'verified-v6'},
     'missing key regenerates its certificate pair');
run_prog("openssl verify -CAfile '$assets/verified-v6.crt' '$assets/verified-v6.crt'");
pass('replacement IPv6 certificate verifies');

done_testing;
