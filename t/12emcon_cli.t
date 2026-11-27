use strict;
use warnings;

use Fcntl qw(:mode);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX qw(WNOHANG);
use Test::More;

my $qlinq_emcon = $ENV{QLINQ_EMCON} // './qlinq-emcon';

sub free_ports {
    my $source = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'udp'
    ) or die "source socket: $!";
    my $destination = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'udp'
    ) or die "destination socket: $!";
    my @ports = ($source->sockport, $destination->sockport);
    close $source;
    close $destination;
    return @ports;
}

sub run_command {
    return system(@_) == 0;
}

sub wait_child {
    my ($pid) = @_;
    for (1 .. 100) {
        my $waited = waitpid($pid, WNOHANG);
        return $? == 0 if $waited == $pid;
        select undef, undef, undef, 0.1;
    }
    kill 'TERM', $pid;
    waitpid($pid, 0);
    return 0;
}

my $directory = tempdir('qlinq-emcon-cli-XXXXXX', TMPDIR => 1, CLEANUP => 1);
my ($source_port, $destination_port) = free_ports();
my $signing_key = "$directory/signer.key";
my $public_key = "$directory/signer.pub";
my $config = "$directory/session.conf";
my $manifest = "$directory/session.bin";
my $signature = "$directory/session.sig";
my $traffic_key = "$directory/traffic.key";

ok(run_command('openssl', 'genpkey', '-algorithm', 'ED25519', '-out',
               $signing_key),
   'create Ed25519 signing key');
chmod 0600, $signing_key;

open my $config_file, '>', $config or die "open config: $!";
print {$config_file} <<"CONFIG";
session_id=random
sender_id=random
flow_id=91
key_epoch=1
initial_packet_number=4611686018427383808
valid_for_seconds=120
source=127.0.0.1:$source_port
destination=127.0.0.1:$destination_port
interface_index=0
replay_window_packets=64
rate_bytes_per_second=100000000
burst_bytes=4096
metadata_repeat_interval_ms=10000
terminal_repeat_count=3
symbol_size=512
repair_symbols=8
stream=7,data,65536,cli-test
CONFIG
close $config_file;

ok(run_command($qlinq_emcon, 'manifest', 'create', $config,
               '--signing-key', $signing_key, '--output', $manifest,
               '--signature', $signature, '--generate-traffic-key',
               $traffic_key, '--public-key-output', $public_key),
   'create signed manifest provisioning set');
is(-s $manifest, 280, 'manifest has canonical one-stream size');
is(-s $signature, 64, 'signature has Ed25519 size');
is(-s $traffic_key, 32, 'generated traffic key has AES-SHA256 secret size');
is((stat($traffic_key))[2] & 0777, 0600, 'generated traffic key is protected');

open my $source_config, '<', $config or die "reopen config: $!";
my $explicit_text = do { local $/; <$source_config> };
close $source_config;
my $now_ms = time() * 1000;
$explicit_text =~ s/valid_for_seconds=120/valid_from_ms=@{[$now_ms - 1000]}\nexpires_at_ms=@{[$now_ms + 120000]}/;
$explicit_text =~ s/key_epoch=1/key_epoch=2/;
my $explicit_config = "$directory/explicit.conf";
open my $explicit_file, '>', $explicit_config or die "explicit config: $!";
print {$explicit_file} $explicit_text;
close $explicit_file;
ok(run_command($qlinq_emcon, 'manifest', 'create', $explicit_config,
               '--signing-key', $signing_key, '--output',
               "$directory/explicit.bin", '--signature',
               "$directory/explicit.sig", '--traffic-key', $traffic_key),
   'accept explicit manifest validity bounds');

open my $key_file, '<', $traffic_key or die "open traffic key: $!";
binmode $key_file;
local $/;
my $key_before = <$key_file>;
close $key_file;
ok(!run_command($qlinq_emcon, 'manifest', 'create', $config,
                '--signing-key', $signing_key, '--output',
                "$directory/duplicate.bin", '--signature',
                "$directory/duplicate.sig", '--generate-traffic-key',
                $traffic_key),
   'refuse to replace an existing generated traffic key');
open $key_file, '<', $traffic_key or die "reopen traffic key: $!";
binmode $key_file;
my $key_after = <$key_file>;
close $key_file;
is($key_after, $key_before, 'failed creation preserves existing traffic key');

my $input = "$directory/input.bin";
my $output = "$directory/output.bin";
my $payload = join '', map { chr(($_ * 29 + 3) & 0xff) } 0 .. 49_999;
open my $input_file, '>', $input or die "open input: $!";
binmode $input_file;
print {$input_file} $payload;
close $input_file;
mkdir "$directory/sender-state", 0700 or die "sender state: $!";
mkdir "$directory/receiver-state", 0700 or die "receiver state: $!";

my @common = ('--manifest', $manifest, '--signature', $signature,
              '--public-key', $public_key, '--traffic-key', $traffic_key,
              '--alias', '7', '--group', '42');
ok(!run_command($qlinq_emcon, 'send', @common, '--state-dir',
                "$directory/sender-state", "$directory/missing/input.bin"),
   'sender reports missing input');
open my $empty, '>', "$directory/empty.bin" or die "empty input: $!";
close $empty;
ok(!run_command($qlinq_emcon, 'send', @common, '--state-dir',
                "$directory/sender-state", "$directory/empty.bin"),
   'sender reports empty input');
is_deeply([glob "$directory/sender-state/*"], [],
          'unusable input consumes no sender packet-number range');
ok(!run_command($qlinq_emcon, 'receive', @common, '--state-dir',
                "$directory/receiver-state", "$directory/missing/output.bin"),
   'receiver startup fails when the output cannot be opened');
is_deeply([glob "$directory/receiver-state/*"], [],
          'output open failure leaves receiver epoch available');

open my $old_output, '>', $output or die "seed output: $!";
print {$old_output} $payload, 'stale output suffix';
close $old_output;
my $receiver = fork();
die "fork receiver: $!" unless defined $receiver;
if ($receiver == 0) {
    open STDOUT, '>', "$directory/receiver.stdout" or exit 127;
    open STDERR, '>', "$directory/receiver.stderr" or exit 127;
    exec $qlinq_emcon, 'receive', @common, '--state-dir',
      "$directory/receiver-state", $output;
    exit 127;
}
for (1 .. 200) {
    last if -z $output;
    select undef, undef, undef, 0.01;
}
ok(-z $output, 'receiver claimed its epoch and opened the output');
open my $other_input, '>', "$directory/other.bin" or die "other input: $!";
print {$other_input} "from another key epoch";
close $other_input;
ok(run_command($qlinq_emcon, 'send', '--manifest', "$directory/explicit.bin",
               '--signature', "$directory/explicit.sig", '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '42',
               '--state-dir', "$directory/sender-state", "$directory/other.bin"),
   'deliver a transfer from another epoch on the same flow and UDP tuple');
ok(run_command($qlinq_emcon, 'send', @common, '--state-dir',
               "$directory/sender-state", '--block-size', '4096', $input),
   'send file through generated manifest');
ok(wait_child($receiver), 'receiver reaches authenticated completion');
open my $output_file, '<', $output or die "open output: $!";
binmode $output_file;
my $received = <$output_file>;
close $output_file;
is($received, $payload, 'receiver reconstructs the input byte-for-byte');

ok(!run_command($qlinq_emcon, 'receive', @common, '--state-dir',
                "$directory/receiver-state", "$directory/reused.bin"),
   'consumed receiver epoch cannot be reopened');
ok(!-e "$directory/reused.bin", 'reused epoch creates no fresh output');
ok(!run_command($qlinq_emcon, 'receive', @common, '--state-dir',
                "$directory/receiver-state", $output),
   'consumed receiver epoch is rejected with an existing output path');
open $output_file, '<', $output or die "reopen output: $!";
binmode $output_file;
my $output_after_reuse = <$output_file>;
close $output_file;
is($output_after_reuse, $payload, 'reused epoch preserves existing output');

chmod 0644, $signing_key;
ok(!run_command($qlinq_emcon, 'manifest', 'create', $config,
                '--signing-key', $signing_key, '--output',
                "$directory/unsafe.bin", '--signature',
                "$directory/unsafe.sig", '--traffic-key', $traffic_key),
   'reject exposed signing key');
ok(!-e "$directory/unsafe.bin" && !-e "$directory/unsafe.sig",
   'signing-key rejection leaves no provisioning outputs');

done_testing();
