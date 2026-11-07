#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'virtual-time recovery latency' => sub {
    plan skip_all => 'ELF clock interception and link audit' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_recovery_latency');
    like($stdout, qr/===RECOVERY LATENCY OK===/, 'delivery, loss, pressure and reconnect meet virtual-time budgets') or diag($stderr);
    ($stderr, $stdout) = run_prog('python3 t/check_transport_engine_link.py t/00util/test_recovery_latency');
    like($stdout, qr/===TRANSPORT ENGINE LINK OK===/, 'recovery timing executes without native I/O') or diag($stderr);
};

subtest 'engine without native I/O implementation' => sub {
    plan skip_all => 'ELF link audit' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_engine');
    like($stdout, qr/===TRANSPORT DRIVE OK===/, 'standalone engine drives real protocol and recovery') or diag($stderr);
    ($stderr, $stdout) = run_prog('python3 t/check_transport_engine_link.py');
    like($stdout, qr/===TRANSPORT ENGINE LINK OK===/, 'native socket, poll and interface implementations are absent') or diag($stderr);
};

subtest 'externally driven transport host' => sub {
    plan skip_all => 'ELF syscall interception' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_drive');
    like($stdout, qr/===TRANSPORT DRIVE OK===/, 'in-memory transport delivery and time pass') or diag($stderr);
};

subtest 'TUN TCP receive coalescing' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_tun_coalesce');
    like($stdout, qr/===TUN COALESCE OK===/, 'ordered compatible prefixes and checksums pass') or diag($stderr);
};

subtest 'TUN TCP segmentation and checksum normalization' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_tun_segment');
    like($stdout, qr/===TUN SEGMENT OK===/,
         'IPv4/IPv6 segments, flags, checksums, bounds and malformed metadata pass') or diag($stderr);
};

subtest 'Linux TUN capability fallback and framing' => sub {
    plan skip_all => 'Linux TUN ioctls and ELF injection' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_tun_vnet');
    like($stdout, qr/===TUN VNET OK===/,
         'negotiation, clean ordinary fallback and framing pass') or diag($stderr);
};

subtest 'bounded owned TUN receive batches' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_tun_receive_batch');
    like($stdout, qr/===TUN RECEIVE BATCH OK===/,
         'callback copies, batch/deadline flush, FIFO, bounds and cancellation pass') or diag($stderr);
};

subtest 'ordinary TUN packet processing without a device' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_tun_packet');
    like($stdout, qr/===TUN PACKET OK===/,
         'both packet directions preserve bytes, bounds, MTU and output capacity') or diag($stderr);
};

subtest 'Quicly errors and fractional RTT integration' => sub {
    plan skip_all => 'ELF linker fault injection' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_quicly_integration');
    like($stdout, qr/===QUICLY INTEGRATION OK===/,
         'fatal errors dispose peers, reconnect works, and sub-ms paths retain precision') or diag($stderr);
};

subtest 'decomposed transport components'  => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_components');
    like($stdout, qr/===TRANSPORT COMPONENTS OK===/,
         'component ownership and lookup tests pass') or diag($stderr);
};

subtest 'UDP GSO grouping and partial sends' => sub {
    plan skip_all => 'Linux UDP_SEGMENT syscall coverage' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_udp_gso_prefix');
    like($stdout, qr/UDP GSO grouping and partial-send fault injection passed/,
         'datagrams remain ordered and accepted prefixes are never replayed') or diag($stderr);
};

subtest 'UDP batch receive boundaries' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_udp_receive');
    like($stdout, qr/===UDP RECEIVE OK===/,
         'native and portable receive preserve boundaries, empty packets and truncation') or diag($stderr);
};

subtest 'UDP GRO receive boundaries and budgets' => sub {
    plan skip_all => 'Linux UDP_GRO syscall coverage' if $^O ne 'linux';
    my ($stderr, $stdout) = run_prog('./t/00util/test_udp_gro');
    like($stdout, qr/===UDP GRO OK===/,
         'aggregates split into bounded datagrams and invalid metadata is dropped') or diag($stderr);
};

subtest 'interface snapshots'  => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_ifmon');
    like($stdout, qr/===IFMON SNAPSHOTS OK===/,
         'interface changes and missing IPv4/IPv6 prefixes retain their semantics') or diag($stderr);
};

subtest 'post-poll receive filtering' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_poll');
    like($stdout, qr/===TRANSPORT POLL OK===/,
         'readiness, timer ticks, receive budgets and replaced sockets preserve progress') or diag($stderr);
};

subtest 'interface discovery and configured bind recovery' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_ifmon');
    like($stdout, qr/===TRANSPORT IFMON OK===/,
         'loopback overrides, explicit IPv4/IPv6 recovery and large queued snapshots pass') or diag($stderr);
};

done_testing;
