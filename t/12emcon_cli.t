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
flow_id=0x5b
key_epoch=1
initial_packet_number=4611686018427383808
valid_for_seconds=120
source=127.0.0.1:$source_port
destination=127.0.0.1:$destination_port
interface_index=0
replay_window_packets=64
rate_bytes_per_second=100000000
burst_bytes=4096
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
my $hex_source_port = sprintf('0x%x', $source_port);
$explicit_text =~ s/valid_for_seconds=120/valid_from_ms=@{[$now_ms - 1000]}\nexpires_at_ms=@{[$now_ms + 120000]}/;
$explicit_text =~ s/key_epoch=1/key_epoch=2/;
$explicit_text =~ s/source=127\.0\.0\.1:\Q$source_port\E/source=127.0.0.1:$hex_source_port/;
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

# Verify completed-file reorder beyond 16 slots (19 buffered objects < 64-packet window).
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
my $reorder_payload = join '', map {
    chr((($_ * 41 + ($_ >> 8) * 13 + 9) & 0xff))
} 0 .. (20 * 256 - 1);
open my $reorder_in_fh, '>', $reorder_input or die "reorder input: $!";
binmode $reorder_in_fh;
print {$reorder_in_fh} $reorder_payload;
close $reorder_in_fh;
ok(run_command($qlinq_emcon, 'send', '--manifest', $reorder_manifest,
               '--signature', $reorder_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '9',
               '--state-dir', "$directory/sender-state", '--block-size', '256',
               $reorder_input),
   'capture 20 single-symbol objects');
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
is(scalar(@captured), 42, 'captured 20*2 object packets + 2 END packets');

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
# Send objects 1..19 (2..39), then delayed object 0 (0..1), then END (40..41).
for my $idx (2 .. 39, 0, 1, 40, 41) {
    $replay_sock->send($captured[$idx]) or die "replay send: $!";
}
close $replay_sock;
ok(wait_child($reorder_rx), 'receiver drains 19 buffered objects once object 0 arrives');
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
is(waitpid($cancel_rx, WNOHANG), 0,
   'blocking receiver is still running before SIGTERM');
kill 'TERM', $cancel_rx;
my $rx_exited_promptly = 0;
for (1 .. 20) {
    if (waitpid($cancel_rx, WNOHANG) == $cancel_rx) {
        $rx_exited_promptly = (($? & 127) == 0 && ($? >> 8) == 1);
        last;
    }
    select undef, undef, undef, 0.05;
}
if (!$rx_exited_promptly) {
    kill 'KILL', $cancel_rx;
    waitpid($cancel_rx, 0);
}
ok($rx_exited_promptly, 'blocking receiver exits promptly on SIGTERM');
open my $rx_err_fh, '<', "$directory/cancel-rx.stderr" or die "rx stderr: $!";
my $rx_stderr = do { local $/; <$rx_err_fh> };
close $rx_err_fh;
like($rx_stderr, qr/qlinq-emcon: interrupted/,
     'receiver stderr records SIGTERM interruption');

my $cancel_capture = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $destination_port, Proto => 'udp'
) or die "cancel capture socket: $!";
mkdir "$directory/cancel-sender-state", 0700 or die "cancel sender state: $!";
my $cancel_tx = fork();
die "fork cancel sender: $!" unless defined $cancel_tx;
if ($cancel_tx == 0) {
    close $cancel_capture;
    open STDOUT, '>', "$directory/cancel-tx.stdout" or exit 127;
    open STDERR, '>', "$directory/cancel-tx.stderr" or exit 127;
    exec $qlinq_emcon, 'send', '--manifest', $slow_manifest,
      '--signature', $slow_sig, '--public-key', $public_key,
      '--traffic-key', $traffic_key, '--alias', '7', '--group', '1',
      '--state-dir', "$directory/cancel-sender-state", '--block-size', '8192',
      $input;
    exit 127;
}
my $first_rin = '';
vec($first_rin, fileno($cancel_capture), 1) = 1;
my $saw_tx_packet = select($first_rin, undef, undef, 3.0) > 0;
my $cancel_packets = 0;
if ($saw_tx_packet) {
    my $datagram = '';
    $cancel_capture->recv($datagram, 2048);
    $cancel_packets++;
}
ok($saw_tx_packet, 'paced sender emitted initial packet before SIGTERM');
is(waitpid($cancel_tx, WNOHANG), 0,
   'paced sender is still waiting in pacer before SIGTERM');
kill 'TERM', $cancel_tx;
my $tx_exited_promptly = 0;
for (1 .. 20) {
    if (waitpid($cancel_tx, WNOHANG) == $cancel_tx) {
        $tx_exited_promptly = (($? & 127) == 0 && ($? >> 8) == 1);
        last;
    }
    select undef, undef, undef, 0.05;
}
if (!$tx_exited_promptly) {
    kill 'KILL', $cancel_tx;
    waitpid($cancel_tx, 0);
}
while (1) {
    my $rin = '';
    vec($rin, fileno($cancel_capture), 1) = 1;
    last unless select($rin, undef, undef, 0.02);
    my $datagram = '';
    $cancel_capture->recv($datagram, 2048);
    $cancel_packets++;
}
close $cancel_capture;
ok($tx_exited_promptly, 'paced sender aborts mid-object promptly on SIGTERM');
cmp_ok($cancel_packets, '<', 10,
       'cancelled sender stops well before completing the 20-symbol object');
open my $tx_err_fh, '<', "$directory/cancel-tx.stderr" or die "tx stderr: $!";
my $tx_stderr = do { local $/; <$tx_err_fh> };
close $tx_err_fh;
like($tx_stderr, qr/qlinq-emcon: interrupted/,
     'sender stderr records SIGTERM interruption');
unlike($tx_stderr, qr/transmission complete/,
       'cancelled sender does not report completion');

# Verify restarted sender rejects changed block-size/input and completes cleanly when compatible.
my $restart_conf = "$directory/restart.conf";
my $restart_manifest = "$directory/restart.bin";
my $restart_sig = "$directory/restart.sig";
open my $restart_cf, '>', $restart_conf or die "restart config: $!";
print {$restart_cf} <<"RESTART_CONFIG";
session_id=random
sender_id=random
flow_id=94
key_epoch=5
initial_packet_number=0
valid_for_seconds=120
source=127.0.0.1:$source_port
destination=127.0.0.1:$destination_port
interface_index=0
replay_window_packets=64
rate_bytes_per_second=100000000
burst_bytes=4096
terminal_repeat_count=2
symbol_size=512
repair_symbols=2
stream=7,data,65536,restart-test
RESTART_CONFIG
close $restart_cf;
ok(run_command($qlinq_emcon, 'manifest', 'create', $restart_conf,
               '--signing-key', $signing_key, '--output', $restart_manifest,
               '--signature', $restart_sig, '--traffic-key', $traffic_key),
   'create restart test manifest');

my $restart_in = "$directory/restart-in.bin";
my $restart_alt = "$directory/restart-alt.bin";
my $restart_bytes = join '', map { chr((($_ * 31 + 17) & 0xff)) } 0 .. 16_383;
my $alt_bytes = $restart_bytes;
substr($alt_bytes, 16_383, 1, chr(ord(substr($alt_bytes, 16_383, 1)) ^ 0xff));
for my $pair ([$restart_in, $restart_bytes], [$restart_alt, $alt_bytes]) {
    open my $fh, '>', $pair->[0] or die "write restart fixture: $!";
    binmode $fh;
    print {$fh} $pair->[1];
    close $fh;
}

mkdir "$directory/restart-tx-state", 0700 or die "restart tx state: $!";
mkdir "$directory/restart-rx-state", 0700 or die "restart rx state: $!";
my $restart_cap = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $destination_port, Proto => 'udp'
) or die "restart capture socket: $!";
ok(run_command($qlinq_emcon, 'send', '--manifest', $restart_manifest,
               '--signature', $restart_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '5',
               '--state-dir', "$directory/restart-tx-state",
               '--block-size', '8192', $restart_in),
   'capture initial 8 KiB block-size transfer');
my @first_run_pkts;
while (1) {
    my $rin = '';
    vec($rin, fileno($restart_cap), 1) = 1;
    last unless select($rin, undef, undef, 0.05);
    my $datagram = '';
    $restart_cap->recv($datagram, 2048);
    push @first_run_pkts, $datagram;
}
close $restart_cap;
is(scalar(@first_run_pkts), 38,
   'captured two 18-packet 8 KiB objects plus two END packets');

my $restart_out = "$directory/restart-out.bin";
open my $restart_seed, '>', $restart_out or die "seed restart out: $!";
print {$restart_seed} 'seed';
close $restart_seed;
my $restart_rx = fork();
die "fork restart receiver: $!" unless defined $restart_rx;
if ($restart_rx == 0) {
    open STDOUT, '>', "$directory/restart-rx.stdout" or exit 127;
    open STDERR, '>', "$directory/restart-rx.stderr" or exit 127;
    exec $qlinq_emcon, 'receive', '--manifest', $restart_manifest,
      '--signature', $restart_sig, '--public-key', $public_key,
      '--traffic-key', $traffic_key, '--alias', '7', '--group', '5',
      '--state-dir', "$directory/restart-rx-state", $restart_out;
    exit 127;
}
for (1 .. 200) {
    last if -z $restart_out;
    select undef, undef, undef, 0.01;
}
ok(-z $restart_out, 'restart receiver ready');

# Deliver only object 0 (first 18 packets) from the interrupted first sender run.
my $partial_sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $source_port,
    PeerAddr  => '127.0.0.1', PeerPort  => $destination_port,
    Proto     => 'udp',
) or die "partial replay socket: $!";
for my $idx (0 .. 17) {
    $partial_sock->send($first_run_pkts[$idx]) or die "partial send: $!";
}
close $partial_sock;
for (1 .. 100) {
    last if (-s $restart_out // 0) == 8192;
    select undef, undef, undef, 0.01;
}
is(-s $restart_out, 8192, 'receiver wrote initial 8 KiB object 0 before restart');

ok(!run_command($qlinq_emcon, 'send', '--manifest', $restart_manifest,
                '--signature', $restart_sig, '--public-key', $public_key,
                '--traffic-key', $traffic_key, '--alias', '7', '--group', '5',
                '--state-dir', "$directory/restart-tx-state",
                '--block-size', '4096', $restart_in),
   'reject restarted transfer on same group with altered block size');
ok(!run_command($qlinq_emcon, 'send', '--manifest', $restart_manifest,
                '--signature', $restart_sig, '--public-key', $public_key,
                '--traffic-key', $traffic_key, '--alias', '7', '--group', '5',
                '--state-dir', "$directory/restart-tx-state",
                '--block-size', '8192', $restart_alt),
   'reject restarted transfer on same group with altered input bytes');
ok(run_command($qlinq_emcon, 'send', '--manifest', $restart_manifest,
               '--signature', $restart_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '5',
               '--state-dir', "$directory/restart-tx-state",
               '--block-size', '8192', $restart_in),
   'allow restarted transfer when input identity and block size match');
ok(wait_child($restart_rx), 'receiver completes after compatible sender restart');
open my $restart_out_fh, '<', $restart_out or die "open restart out: $!";
binmode $restart_out_fh;
my $restart_received = do { local $/; <$restart_out_fh> };
close $restart_out_fh;
is($restart_received, $restart_bytes,
   'restarted transfer delivers exact 16,384 bytes without splicing');

# Verify END terminal bound rejects buffered or subsequent out-of-range objects.
my $end_conf = "$directory/end-bound.conf";
my $end_manifest = "$directory/end-bound.bin";
my $end_sig = "$directory/end-bound.sig";
open my $end_cf, '>', $end_conf or die "end-bound config: $!";
print {$end_cf} <<"END_CONFIG";
session_id=random
sender_id=random
flow_id=95
key_epoch=6
initial_packet_number=0
valid_for_seconds=120
source=127.0.0.1:$source_port
destination=127.0.0.1:$destination_port
interface_index=0
replay_window_packets=64
rate_bytes_per_second=100000000
burst_bytes=4096
terminal_repeat_count=1
symbol_size=512
repair_symbols=1
stream=7,data,65536,end-bound-test
END_CONFIG
close $end_cf;
ok(run_command($qlinq_emcon, 'manifest', 'create', $end_conf,
               '--signing-key', $signing_key, '--output', $end_manifest,
               '--signature', $end_sig, '--traffic-key', $traffic_key),
   'create terminal-bound test manifest');

my $one_block_in = "$directory/one-block.bin";
my $two_block_in = "$directory/two-block.bin";
open my $one_fh, '>', $one_block_in or die "one-block: $!";
binmode $one_fh;
print {$one_fh} ('A' x 256);
close $one_fh;
open my $two_fh, '>', $two_block_in or die "two-block: $!";
binmode $two_fh;
print {$two_fh} ('A' x 256), ('B' x 256);
close $two_fh;

mkdir "$directory/end-tx-state", 0700 or die "end tx state: $!";
my $end_cap = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $destination_port, Proto => 'udp'
) or die "end capture socket: $!";
ok(run_command($qlinq_emcon, 'send', '--manifest', $end_manifest,
               '--signature', $end_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '11',
               '--state-dir', "$directory/end-tx-state",
               '--block-size', '256', $two_block_in),
   'capture two-object group 11 stream');
my @two_obj_pkts;
while (1) {
    my $rin = '';
    vec($rin, fileno($end_cap), 1) = 1;
    last unless select($rin, undef, undef, 0.05);
    my $datagram = '';
    $end_cap->recv($datagram, 2048);
    push @two_obj_pkts, $datagram;
}
# Capture a valid END(final_object_id = 0) on the same group in a fresh sender state dir
# seeded after the two-object packet numbers.
mkdir "$directory/end-tx2-state", 0700 or die "end tx2 state: $!";
ok(run_command($qlinq_emcon, 'send', '--manifest', $end_manifest,
               '--signature', $end_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '10',
               '--state-dir', "$directory/end-tx2-state",
               '--reservation-packets', '16', '--block-size', '256',
               $one_block_in),
   'advance second sender state past two-object packet numbers');
while (1) {
    my $rin = '';
    vec($rin, fileno($end_cap), 1) = 1;
    last unless select($rin, undef, undef, 0.05);
    my $datagram = '';
    $end_cap->recv($datagram, 2048);
}
ok(run_command($qlinq_emcon, 'send', '--manifest', $end_manifest,
               '--signature', $end_sig, '--public-key', $public_key,
               '--traffic-key', $traffic_key, '--alias', '7', '--group', '11',
               '--state-dir', "$directory/end-tx2-state",
               '--block-size', '256', $one_block_in),
   'capture authenticated END(0) on group 11 at higher packet number');
my @end0_pkts;
while (1) {
    my $rin = '';
    vec($rin, fileno($end_cap), 1) = 1;
    last unless select($rin, undef, undef, 0.05);
    my $datagram = '';
    $end_cap->recv($datagram, 2048);
    push @end0_pkts, $datagram;
}
close $end_cap;
is(scalar(@two_obj_pkts), 5, 'captured obj0 (0..1), obj1 (2..3), END(1) (4)');
is(scalar(@end0_pkts), 3, 'captured higher-PN obj0 (0..1) and END(0) (2)');

for my $case (
    ['buffered object past END(0)', [$two_obj_pkts[2], $end0_pkts[2], $two_obj_pkts[0]]],
    ['object past already-accepted END(0)', [$end0_pkts[2], $two_obj_pkts[2], $two_obj_pkts[0]]],
) {
    my ($label, $sequence) = @$case;
    my $rx_dir = tempdir('qlinq-end-rx-XXXXXX', DIR => $directory);
    chmod 0700, $rx_dir;
    my $case_out = "$rx_dir/out.bin";
    open my $seed, '>', $case_out or die "seed end out: $!";
    print {$seed} 'seed';
    close $seed;
    my $pid = fork();
    die "fork end-bound rx: $!" unless defined $pid;
    if ($pid == 0) {
        open STDOUT, '>', "$rx_dir/stdout" or exit 127;
        open STDERR, '>', "$rx_dir/stderr" or exit 127;
        exec $qlinq_emcon, 'receive', '--manifest', $end_manifest,
          '--signature', $end_sig, '--public-key', $public_key,
          '--traffic-key', $traffic_key, '--alias', '7', '--group', '11',
          '--state-dir', $rx_dir, $case_out;
        exit 127;
    }
    for (1 .. 200) {
        last if -z $case_out;
        select undef, undef, undef, 0.01;
    }
    my $inj = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => $source_port,
        PeerAddr  => '127.0.0.1', PeerPort  => $destination_port,
        Proto     => 'udp',
    ) or die "inject end-bound socket: $!";
    for my $pkt (@$sequence) {
        $inj->send($pkt) or die "inject send: $!";
    }
    close $inj;
    ok(!wait_child($pid), "receiver fails on $label");
    open my $err_fh, '<', "$rx_dir/stderr" or die "open end stderr: $!";
    my $err_text = do { local $/; <$err_fh> };
    close $err_fh;
    like($err_text, qr/inconsistent terminal object range/,
         "receiver reports terminal range violation for $label");
}

done_testing();
