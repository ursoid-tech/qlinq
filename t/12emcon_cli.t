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

for my $mixed_field ("valid_from_ms=@{[$now_ms - 1000]}",
                     "expires_at_ms=@{[$now_ms + 120000]}") {
    open my $mixed_in, '<', $config or die "reopen config: $!";
    my $mixed_text = do { local $/; <$mixed_in> };
    close $mixed_in;
    $mixed_text .= "$mixed_field\n";
    my $mixed_config = "$directory/mixed.conf";
    open my $mixed_out, '>', $mixed_config or die "mixed config: $!";
    print {$mixed_out} $mixed_text;
    close $mixed_out;
    ok(!run_command($qlinq_emcon, 'manifest', 'create', $mixed_config,
                    '--signing-key', $signing_key, '--output',
                    "$directory/mixed.bin", '--signature',
                    "$directory/mixed.sig", '--traffic-key', $traffic_key),
       "reject valid_for_seconds combined with $mixed_field");
}

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
chmod 0600, $signing_key;

# Verify full 16-slot reorder drain when object 0 arrives after objects 1..16.
my $reorder_conf = "$directory/reorder.conf";
my $reorder_manifest = "$directory/reorder.bin";
my $reorder_sig = "$directory/reorder.sig";
open my $reorder_cf, '>', $reorder_conf or die "reorder config: $!";
print {$reorder_cf} <<"REORDER_CONFIG";
session_id=random
sender_id=random
flow_id=92
key_epoch=3
initial_packet_number=10
valid_for_seconds=120
source=127.0.0.1:$source_port
destination=127.0.0.1:$destination_port
interface_index=0
replay_window_packets=64
rate_bytes_per_second=100000000
burst_bytes=4096
metadata_repeat_interval_ms=10000
terminal_repeat_count=2
symbol_size=512
repair_symbols=1
stream=7,data,65536,reorder-test
REORDER_CONFIG
close $reorder_cf;
ok(run_command($qlinq_emcon, 'manifest', 'create', $reorder_conf,
               '--signing-key', $signing_key, '--output', $reorder_manifest,
               '--signature', $reorder_sig, '--traffic-key', $traffic_key),
   'create reorder test manifest');

my $capture_sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $destination_port, Proto => 'udp'
) or die "capture socket: $!";
my $reorder_input = "$directory/reorder-in.bin";
my $reorder_payload = join '', map { chr(($_ * 41 + 9) & 0xff) } 0 .. (17 * 256 - 1);
open my $reorder_in_fh, '>', $reorder_input or die "reorder input: $!";
binmode $reorder_in_fh;
print {$reorder_in_fh} $reorder_payload;
close $reorder_in_fh;
ok(run_command($qlinq_emcon, 'send', '--manifest', $reorder_manifest,
               '--signature', $reorder_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '9',
               '--state-dir', "$directory/sender-state", '--block-size', '256',
               $reorder_input),
   'capture 17 single-symbol objects');
my @captured;
while (1) {
    my $rin = '';
    vec($rin, fileno($capture_sock), 1) = 1;
    last unless select($rin, undef, undef, 0.05);
    my $datagram = '';
    $capture_sock->recv($datagram, 2048);
    push @captured, $datagram;
}
close $capture_sock;
is(scalar(@captured), 37, 'captured SESSION + 17*2 object packets + 2 END packets');

my $reorder_output = "$directory/reorder-out.bin";
open my $seed_fh, '>', $reorder_output or die "seed reorder output: $!";
print {$seed_fh} 'seed';
close $seed_fh;
my $reorder_rx = fork();
die "fork reorder receiver: $!" unless defined $reorder_rx;
if ($reorder_rx == 0) {
    open STDOUT, '>', "$directory/reorder.stdout" or exit 127;
    open STDERR, '>', "$directory/reorder.stderr" or exit 127;
    exec $qlinq_emcon, 'receive', '--manifest', $reorder_manifest,
      '--signature', $reorder_sig, '--public-key', $public_key,
      '--traffic-key', $traffic_key, '--alias', '7', '--group', '9',
      '--state-dir', "$directory/receiver-state", $reorder_output;
    exit 127;
}
for (1 .. 200) {
    last if -z $reorder_output;
    select undef, undef, undef, 0.01;
}
ok(-z $reorder_output, 'reorder receiver ready');

my $replay_sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $source_port,
    PeerAddr  => '127.0.0.1', PeerPort  => $destination_port,
    Proto     => 'udp',
) or die "replay socket: $!";
# Send SESSION (0), objects 1..16 (3..34), then delayed object 0 (1..2), then END (35..36).
for my $idx (0, 3 .. 34, 1, 2, 35, 36) {
    $replay_sock->send($captured[$idx]) or die "replay send: $!";
}
close $replay_sock;
ok(wait_child($reorder_rx), 'receiver drains 16 buffered objects once object 0 arrives');
open my $reorder_out_fh, '<', $reorder_output or die "open reorder output: $!";
binmode $reorder_out_fh;
my $reordered_bytes = do { local $/; <$reorder_out_fh> };
close $reorder_out_fh;
is($reordered_bytes, $reorder_payload, 'reordered stream reconstructed byte-for-byte');

# Verify prompt SIGTERM cancellation on paced sender and blocking receiver.
my $slow_conf = "$directory/slow.conf";
my $slow_manifest = "$directory/slow.bin";
my $slow_sig = "$directory/slow.sig";
open my $slow_cf, '>', $slow_conf or die "slow config: $!";
print {$slow_cf} <<"SLOW_CONFIG";
session_id=random
sender_id=random
flow_id=93
key_epoch=4
initial_packet_number=0
valid_for_seconds=120
source=127.0.0.1:$source_port
destination=127.0.0.1:$destination_port
interface_index=0
replay_window_packets=64
rate_bytes_per_second=500
burst_bytes=1200
metadata_repeat_interval_ms=10000
terminal_repeat_count=4
symbol_size=512
repair_symbols=4
stream=7,data,65536,cancel-test
SLOW_CONFIG
close $slow_cf;
ok(run_command($qlinq_emcon, 'manifest', 'create', $slow_conf,
               '--signing-key', $signing_key, '--output', $slow_manifest,
               '--signature', $slow_sig, '--traffic-key', $traffic_key),
   'create slow paced manifest for cancellation test');

my $cancel_rx_out = "$directory/cancel-rx.bin";
open my $cancel_seed, '>', $cancel_rx_out or die "seed cancel output: $!";
print {$cancel_seed} 'seed';
close $cancel_seed;
my $cancel_rx = fork();
die "fork cancel receiver: $!" unless defined $cancel_rx;
if ($cancel_rx == 0) {
    open STDOUT, '>', "$directory/cancel-rx.stdout" or exit 127;
    open STDERR, '>', "$directory/cancel-rx.stderr" or exit 127;
    exec $qlinq_emcon, 'receive', '--manifest', $slow_manifest,
      '--signature', $slow_sig, '--public-key', $public_key,
      '--traffic-key', $traffic_key, '--alias', '7', '--group', '1',
      '--state-dir', "$directory/receiver-state", $cancel_rx_out;
    exit 127;
}
for (1 .. 200) {
    last if -z $cancel_rx_out;
    select undef, undef, undef, 0.01;
}
kill 'TERM', $cancel_rx;
my $rx_exited_promptly = 0;
for (1 .. 20) {
    if (waitpid($cancel_rx, WNOHANG) == $cancel_rx) {
        $rx_exited_promptly = ($? != 0);
        last;
    }
    select undef, undef, undef, 0.05;
}
ok($rx_exited_promptly, 'blocking receiver exits promptly on SIGTERM');

mkdir "$directory/cancel-sender-state", 0700 or die "cancel sender state: $!";
my $cancel_tx = fork();
die "fork cancel sender: $!" unless defined $cancel_tx;
if ($cancel_tx == 0) {
    open STDOUT, '>', "$directory/cancel-tx.stdout" or exit 127;
    open STDERR, '>', "$directory/cancel-tx.stderr" or exit 127;
    exec $qlinq_emcon, 'send', '--manifest', $slow_manifest,
      '--signature', $slow_sig, '--public-key', $public_key,
      '--traffic-key', $traffic_key, '--alias', '7', '--group', '1',
      '--state-dir', "$directory/cancel-sender-state", '--block-size', '8192',
      $input;
    exit 127;
}
for (1 .. 200) {
    last if glob "$directory/cancel-sender-state/sender-*";
    select undef, undef, undef, 0.01;
}
select undef, undef, undef, 0.1;
kill 'TERM', $cancel_tx;
my $tx_exited_promptly = 0;
for (1 .. 20) {
    if (waitpid($cancel_tx, WNOHANG) == $cancel_tx) {
        $tx_exited_promptly = ($? != 0);
        last;
    }
    select undef, undef, undef, 0.05;
}
if (!$tx_exited_promptly) {
    kill 'KILL', $cancel_tx;
    waitpid($cancel_tx, 0);
}
ok($tx_exited_promptly, 'paced sender aborts mid-object promptly on SIGTERM');

done_testing();
