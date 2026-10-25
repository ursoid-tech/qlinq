import copy
import argparse
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
import transit_demo
HELPERS = vars(transit_demo)
ANALYZE = HELPERS['analyze']


class ProvenanceTests(unittest.TestCase):
    def test_checkout_has_its_own_revision(self):
        identity = HELPERS['git_identity'](ROOT)
        self.assertEqual(identity['commit'], subprocess.check_output(
            ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip())
        self.assertEqual(len(identity['tracked_diff_sha256']), 64)

    def test_subdirectory_cannot_inherit_parent_revision(self):
        self.assertIsNone(HELPERS['git_identity'](ROOT / 'src'))

    def test_symlink_to_checkout_keeps_its_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'linked-dependency'
            link.symlink_to(ROOT / 'deps/quicly', target_is_directory=True)
            self.assertEqual(HELPERS['git_identity'](link), HELPERS['git_identity'](ROOT / 'deps/quicly'))


class ReliableProfileTests(unittest.TestCase):
    def test_frozen_profile_preserves_loss_and_recovery_load(self):
        runner = runpy.run_path(str(ROOT / 'examples/multipath_reliable_qualification'))
        profile = json.loads(runner['PROFILE'].read_text())
        args = SimpleNamespace(case='loss', seed=3, fault_path=2, fault_direction='both',
            sender_cpu=0, receiver_cpu=1, router_cpus='2,3', output_dir='/tmp/profile-test')
        command = runner['command'](profile, args)
        def value(option):
            return command[command.index('--' + option) + 1]
        for key, expected in {'mode': 'reliable', 'seconds': '400', 'fault-at': '300',
                'restore-at': '330', 'mbps': '1200', 'recovery-mbps': '2300',
                'seed': '3', 'fault-path': '2', 'fault-direction': 'both',
                'receive-memory-bytes': '33554432',
                'stream-egress-bytes': '25165824'}.items():
            self.assertEqual(value(key), expected)
        self.assertNotIn('seed', profile['common'])
        args.case = 'healthy'
        command = runner['command'](profile, args)
        self.assertEqual(value('mbps'), '2300')
        self.assertNotIn('--recovery-mbps', command)
        args.send_batch = 64
        command = runner['command'](profile, args)
        self.assertEqual(value('send-batch'), '64')
        reduced = json.loads((ROOT / 'examples/profiles/reliable-reduced-rate-v1.json').read_text())
        args.case = 'outage'
        command = runner['command'](reduced, args)
        self.assertEqual(value('mbps'), '700')
        self.assertEqual(value('recovery-mbps'), '900')
        self.assertEqual(value('recovery-restored-path-min-mbps'), '100')

    def test_refuses_to_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([str(ROOT / 'examples/multipath_reliable_qualification'),
                '--case', 'healthy', '--seed', '1', '--sender-cpu', '0',
                '--receiver-cpu', '1', '--router-cpus', '2,3', '--output-dir', directory],
                capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'prior evidence is never overwritten', result.stderr)

    def test_reverse_only_cannot_claim_restored_forward_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'trial'
            result = subprocess.run([str(ROOT / 'examples/multipath_reliable_qualification'),
                '--case', 'loss', '--seed', '1', '--fault-direction', 'reverse',
                '--sender-cpu', '0', '--receiver-cpu', '1', '--router-cpus', '2,3',
                '--output-dir', str(out)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'restored forward capacity', result.stderr)
            self.assertFalse(out.exists())

    def test_controller_arguments_are_exposed(self):
        result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'), '--help'], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'--congestion-control', result.stdout)
        self.assertIn(b'--pacing', result.stdout)
        self.assertIn(b'--service-wait-ms', result.stdout)
        self.assertIn(b'--send-batch', result.stdout)
        self.assertIn(b'--recovery-restored-path-min-mbps', result.stdout)
        self.assertIn(b'--receive-delivery', result.stdout)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(mbps=10, seconds=10, record_bytes=1000,
            warmup=1, scenario='healthy', calibration_wire_mbps=12,
            fault_at=4, restore_at=8, reaction_seconds=1, rtt_ms=40, rate_mbps=1000, paths=2, fault_path=0)
        self.tx = [{'event': 'summary', 'offered': 12500, 'admitted': 12500}]
        self.rx = [{'event': 'sample', 'time': t, 'interval_start': t-1,
                    'received': t*1250, 'received_bytes': t*1250000,
                    'latency_histogram_ms': [[19, 1250]]} for t in range(2, 11)]
        self.rx += [{'event': 'summary', 'received': 12500, 'corrupt': 0,
                     'duplicates': 0, 'outside_reorder_window': 0}]
        self.samples = [{'time': t, 'forward': [{'bytes': t*600000}, {'bytes': t*1200000}]} for t in range(2, 11)]
        for sample in self.samples:
            sample['sent'] = copy.deepcopy(sample['forward'])

    def report(self, **kwargs):
        return ANALYZE(self.tx, self.rx, self.samples, self.args, kwargs.get('exits', [0, 0]), kwargs.get('faults', ()))

    def test_callback_report_requires_zero_public_record_copies(self):
        self.args.receive_delivery = 'callback'
        self.tx[0]['receive_delivery'] = 'queue'
        self.rx[-1].update(receive_delivery='callback', record_events_queued=0,
                           record_payload_bytes_copied=0,
                           record_callbacks_accepted=12500,
                           record_callbacks_rejected=0)
        result = self.report()
        self.assertTrue(result['checks']['receive_delivery_mode'])
        self.assertTrue(result['checks']['callback_avoids_public_record_copies'])
        self.rx[-1]['record_payload_bytes_copied'] = 1
        self.assertFalse(self.report()['checks']['callback_avoids_public_record_copies'])

    def test_directional_fault_targets_and_restoration(self):
        self.args.scenario = 'outage'
        self.args.fault_path = 1
        calls = []
        topo = SimpleNamespace(shape=lambda *a, **k: calls.append((a, k)))
        for direction, devices in [('forward', ['f1']), ('reverse', ['r1']), ('both', ['f1', 'r1'])]:
            self.args.fault_direction = direction
            calls.clear()
            HELPERS['apply_path_fault'](topo, self.args, [10, 20], ['f0', 'f1'], ['r0', 'r1'], True)
            self.assertEqual(calls, [((20, dev, 1000, 20, 100), {'replace': True}) for dev in devices])
            calls.clear()
            HELPERS['apply_path_fault'](topo, self.args, [10, 20], ['f0', 'f1'], ['r0', 'r1'], False)
            self.assertEqual(calls, [((20, dev, 1000, 20, 0), {'replace': True}) for dev in devices])

    def test_seeded_loss_and_restoration_keep_directed_path_seeds(self):
        self.args.scenario = 'loss'
        self.args.loss_percent = 1
        self.args.seed = 0xffffffff
        self.args.fault_direction = 'both'
        self.args.fault_path = 1
        seeds = [HELPERS['netem_seed'](self.args, p, d)
                 for p in range(4) for d in ('forward', 'reverse')]
        self.assertEqual(seeds, [0xffffffff, 1, 2, 3, 4, 5, 6, 7])
        calls = []
        topo = SimpleNamespace(shape=lambda *a, **k: calls.append((a, k)))
        for fault, loss in ((True, 1), (False, 0)):
            calls.clear()
            HELPERS['apply_path_fault'](topo, self.args, [10, 20], ['f0', 'f1'], ['r0', 'r1'], fault)
            self.assertEqual(calls, [((20, dev, 1000, 20, loss), {'replace': True, 'seed': seed})
                                     for dev, seed in (('f1', 2), ('r1', 3))])

    def test_netem_command_sets_seed_only_when_requested(self):
        topo = HELPERS['Topology']()
        calls = []
        topo.cmd = lambda *a: calls.append(a)
        topo.shape(10, 'testdev', 1000, 20, 1, seed=123)
        self.assertEqual(calls[-1][-4:], ('loss', '1%', 'seed', 123))
        calls.clear()
        topo.shape(10, 'testdev', 1000, 20, replace=True)
        self.assertNotIn('seed', calls[-1])

    def test_loss_cli_rejects_invalid_seeds_and_percentages(self):
        for option, value in (('--seed', '0'), ('--seed', '-1'), ('--seed', '4294967296'),
                              ('--loss-percent', '0'), ('--loss-percent', '101'), ('--loss-percent', 'nan')):
            result = subprocess.run(['python3', str(ROOT / 'examples/multipath_transit_demo'),
                                     '--output-dir', '/unused', option, value], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_reverse_fault_uses_reverse_injection(self):
        self.args.scenario = 'outage'
        self.args.fault_direction = 'reverse'
        faults = [{'event': 'fault', 'time': 4.1}, {'event': 'restore', 'time': 8.1}]
        for sample in self.samples:
            t = sample['time']
            sample['reverse_sent'] = [{'bytes': min(t, 5)*1000}, {'bytes': t*1000}]
        report = self.report(faults=faults)
        self.assertTrue(report['checks']['reverse_fault_path_exercised'])
        self.assertTrue(report['checks']['degraded_reverse_sent_wire_share_below_10pct'])
        self.assertNotIn('degraded_sent_wire_share_below_10pct', report['checks'])
        self.assertIsNone(report['degraded_sent_wire_fraction'])
        self.args.fault_direction = 'both'
        report = self.report(faults=faults)
        self.assertTrue(report['checks']['degraded_reverse_sent_wire_share_below_10pct'])
        self.assertFalse(report['checks']['degraded_sent_wire_share_below_10pct'])
        for sample in self.samples:
            sample.pop('reverse_sent')
        self.assertFalse(self.report(faults=faults)['checks']['reverse_fault_path_exercised'])

    def test_phase_windows_exclude_fault_and_restore_mutation_intervals(self):
        self.args.scenario = 'outage'
        report = self.report(faults=[
            {'event': 'fault', 'started_at': 3.5, 'time': 4.1},
            {'event': 'restore', 'started_at': 7.5, 'time': 8.1}])
        self.assertEqual(report['fault_application_rates']['before']['end'], 3)
        self.assertEqual(report['fault_application_rates']['degraded']['start'], 6)
        self.assertEqual(report['fault_application_rates']['degraded']['end'], 7)
        self.assertEqual(report['fault_application_latency']['before']['end'], 3)
        self.assertEqual(report['fault_application_latency']['degraded']['end'], 7)

    def test_wire_share_weights_time_and_rejects_missing_or_reset_counters(self):
        fraction = HELPERS['wire_fraction']
        rows = [dict(start=0, time=1, rates=[9, 1]), dict(start=1, time=10, rates=[0, 10])]
        self.assertAlmostEqual(fraction(rows, 'rates', 0, 2), .09)
        self.assertIsNone(fraction([], 'rates', 0, 2))
        rows[1]['rates'] = [0]
        self.assertIsNone(fraction(rows, 'rates', 0, 2))
        for invalid in (-1, float('nan'), float('inf')):
            rows[1]['rates'] = [invalid, 10]
            self.assertIsNone(fraction(rows, 'rates', 0, 2))

    def test_direction_options_reject_false_recovery_claims(self):
        for options in (['--fault-direction', 'reverse'],
                        ['--scenario', 'calibration', '--fault-direction', 'both'],
                        ['--scenario', 'outage', '--fault-direction', 'reverse', '--recovery-mbps', '2300']):
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                                     '--output-dir', '/unused', *options], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('requires', result.stderr)

    def test_heterogeneous_profiles_and_fault_restoration(self):
        self.args.path_rates_mbps = [1000, 250]
        self.args.path_rtts_ms = [20, 80]
        profile = HELPERS['path_profile']
        self.assertEqual(profile(self.args, 0), (1000, 10, 0))
        self.assertEqual(profile(self.args, 1), (250, 40, 0))
        for scenario, expected in [('capacity', (25, 40, 0)),
                                   ('delay', (250, 140, 0)),
                                   ('loss', (250, 40, 5)),
                                   ('outage', (250, 40, 100))]:
            self.args.scenario = scenario
            self.assertEqual(profile(self.args, 1, fault=True), expected)
            self.assertEqual(profile(self.args, 1), (250, 40, 0))
        self.args.scenario = 'healthy'
        self.assertEqual(self.report()['path_profiles'], [
            {'path': 0, 'rate_mbps': 1000, 'rtt_ms': 20},
            {'path': 1, 'rate_mbps': 250, 'rtt_ms': 80}])

    def test_path_profile_defaults_and_validation(self):
        self.assertEqual(HELPERS['path_profile'](self.args, 1), (1000, 20, 0))
        parse = HELPERS['positive_list']
        self.assertEqual(parse('1000,500,250.5'), [1000, 500, 250.5])
        for value in ('', '1,,2', '1,0', '1,-2', '1,nan', '1,inf'):
            with self.assertRaises(argparse.ArgumentTypeError):
                parse(value)
        for options in (['--path-rates-mbps', '1000,500'],
                        ['--path-rtts-ms', '20,40'],
                        ['--scenario', 'calibration', '--path-rates-mbps', '1000,500,250'],
                        ['--scenario', 'capacity', '--seconds', '90',
                         '--fault-at', '30', '--restore-at', '40',
                         '--path-rtts-ms', '1000,40,40']):
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                                     '--output-dir', '/unused', *options],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_reaction_window_uses_faulted_path_rtt(self):
        self.args.scenario = 'capacity'
        self.args.path_rtts_ms = [400, 40]
        # If the uniform 40 ms default were used, all settled samples would
        # show successful avoidance. At 400 ms there is no settled interval.
        for sample in self.samples:
            sample['sent'][0]['bytes'] = min(sample['time'], 4) * 600000
        result = self.report(faults=[{'event': 'fault', 'time': 4},
                                    {'event': 'restore', 'time': 8}])
        self.assertFalse(result['checks']['degraded_sent_wire_share_below_10pct'])

    def test_namespace_udp_drop_counters(self):
        counters = HELPERS['parse_snmp'](
            'Ip: Forwarding DefaultTTL\nIp: 1 64\n'
            'Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n'
            'Udp: 100 0 7 200 7 0\n')
        self.assertEqual(counters['RcvbufErrors'], 7)
        self.assertEqual(counters['InDatagrams'], 100)
        with self.assertRaises(RuntimeError):
            HELPERS['parse_snmp']('Ip: Forwarding\nIp: 1\n')

    def test_offloads_must_be_observed_disabled(self):
        topology = HELPERS['Topology']()
        calls = []
        features = {name: 'off' for name in HELPERS['DISABLED_OFFLOADS'].values()}

        def fake_command(pid, *args):
            calls.append((pid, args))
            return 'Features for test0:\n' + ''.join(
                f'\t{name}: {state} [fixed]\n' for name, state in features.items())

        topology.cmd = fake_command
        topology.disable_offloads(123, 'test0')
        self.assertIn('tx-udp-segmentation', calls[0][1])
        self.assertIn('rx-udp-gro-forwarding', calls[0][1])
        self.assertEqual(topology.offloads[-1]['features'], features)
        # Successful ethtool -K is insufficient if readback remains on.
        features['tx-udp-segmentation'] = 'on'
        with self.assertRaisesRegex(RuntimeError, 'tx-udp-segmentation'):
            topology.disable_offloads(123, 'test0')
        self.assertEqual(topology.offloads[-1]['features']['tx-udp-segmentation'], 'on')
        del features['tx-udp-segmentation']
        with self.assertRaisesRegex(RuntimeError, 'tx-udp-segmentation'):
            topology.disable_offloads(123, 'test0')

    def test_router_steering_masks_and_readback(self):
        self.assertEqual(HELPERS['router_cpus']('2,3'), (2, 3))
        self.assertEqual(HELPERS['cpu_mask'](2), '00000004')
        self.assertEqual(HELPERS['cpu_mask'](33), '00000002,00000000')
        topology = HELPERS['Topology']()
        calls = []

        def fake_command(pid, *args):
            calls.append((pid, args))
            return '00000002,00000000\n'

        topology.cmd = fake_command
        topology.steer_receive(123, 's1b', 33, '/tmp/private-rps')
        self.assertEqual(calls[0][0], 123)
        self.assertEqual(calls[0][1][:2], ('unshare', '-m'))
        self.assertEqual(calls[0][1][-3:], ('/tmp/private-rps', 's1b', '00000002,00000000'))
        self.assertEqual(topology.rps[0]['cpu'], 33)
        with self.assertRaisesRegex(RuntimeError, 'RPS readback mismatch'):
            topology.steer_receive(123, 's1b', 2, '/tmp/private-rps')

    def test_healthy_fixture_does_not_claim_qualification(self):
        result = self.report()
        self.assertTrue(result['passed'])
        self.assertFalse(result['qualified'])
        self.assertEqual(result['steady_goodput_mbps'], 10)
        self.assertEqual(result['steady_forward_wire_mbps'], 14.4)

    def test_catch_up_after_restore_cannot_hide_fault_stall(self):
        self.args.scenario = 'capacity'
        faults = [{'event': 'fault', 'time': 4}, {'event': 'restore', 'time': 8}]
        for row in self.rx:
            if row.get('event') == 'sample' and 5 <= row['time'] < 8:
                row['received_bytes'] = 5 * 1250000
        report = self.report(faults=faults)
        self.assertTrue(report['checks']['steady_goodput_90pct_offer'])
        self.assertTrue(report['checks']['generator_kept_up'])
        self.assertTrue(report['checks']['pre_fault_goodput_90pct_offer'])
        self.assertFalse(report['checks']['degraded_goodput_90pct_control'])
        self.assertEqual(report['fault_application_rates']['degraded']['mbps'], 0)
        self.assertEqual(report['fault_application_rates']['degraded']['end'], 7)

    def test_fault_application_measurements_require_valid_phase_counters(self):
        self.args.scenario = 'capacity'
        faults = [{'event': 'fault', 'time': 4}, {'event': 'restore', 'time': 8}]
        report = self.report(faults=faults)
        self.assertTrue(report['checks']['degraded_goodput_90pct_control'])
        self.assertAlmostEqual(report['degraded_sent_wire_fraction'], 1/3)
        self.rx[4]['received_bytes'] = 0  # t=6 resets during degraded phase
        report = self.report(faults=faults)
        self.assertFalse(report['checks']['fault_application_measurements_complete'])
        self.assertFalse(report['checks']['degraded_goodput_90pct_control'])
        self.rx = [row for row in self.rx if row.get('time', 100) not in (5, 6)]
        report = self.report(faults=faults)
        self.assertIsNone(report['fault_application_rates']['degraded'])

    def test_fault_latency_uses_record_weighted_phase_distribution(self):
        self.args.scenario = 'capacity'
        faults = [{'event': 'fault', 'time': 4}, {'event': 'restore', 'time': 8}]
        # A very slow second with few completions must not dominate p99 of the
        # combined phase; equal-weight percentile averages would be wrong.
        for row in self.rx:
            if row.get('time') == 6:
                row.update(received=6251, latency_histogram_ms=[[999, 1]])
            elif row.get('time') == 7:
                row.update(received=8750, latency_histogram_ms=[[19, 2499]])
        result = self.report(faults=faults)
        self.assertTrue(result['checks']['degraded_p99_within_control_plus_100ms'])
        phase = result['fault_application_latency']['degraded']
        self.assertEqual((phase['records'], phase['p99_ms']), (2500, 20))
        self.rx[5]['latency_histogram_ms'] = [[120, 2499]]  # t=7, upper bound 121 ms
        self.assertFalse(self.report(faults=faults)['checks']['degraded_p99_within_control_plus_100ms'])

    def test_latency_missing_invalid_censored_and_empty_evidence(self):
        measure = HELPERS['latency_window']
        original = copy.deepcopy(self.rx)
        for invalid in (None, [[19, -1]], [[19, 1250], [19, 1]],
                        [[10001, 1250]], [[-1, 1250]], [[19, True]], [[19, 1249]]):
            self.rx = copy.deepcopy(original)
            self.rx[4]['latency_histogram_ms'] = invalid
            self.assertIsNone(measure(self.rx, 5, 8))
        self.rx = copy.deepcopy(original)
        self.rx[4]['interval_start'] = 4.5
        self.assertIsNone(measure(self.rx, 5, 8))
        self.rx = copy.deepcopy(original)
        self.rx[4]['latency_histogram_ms'] = [[10000, 1250]]
        phase = measure(self.rx, 5, 8)
        self.assertIsNone(phase['p99_ms'])
        self.assertTrue(phase['p99_censored'])
        self.rx[4]['received'] = self.rx[5]['received'] = self.rx[3]['received']
        self.rx[4]['latency_histogram_ms'] = self.rx[5]['latency_histogram_ms'] = []
        self.assertEqual(measure(self.rx, 5, 8)['records'], 0)
        self.assertIsNone(measure(self.rx, 7, 8))

    def test_latency_excludes_transition_restore_and_drain(self):
        for row in self.rx:
            if row.get('event') == 'sample' and row['time'] in (5, 8, 9, 10):
                row['latency_histogram_ms'] = [[999, 1250]]
        phase = HELPERS['latency_window'](self.rx, 5, 8)
        self.assertEqual(phase['p99_ms'], 20)
        self.assertEqual((phase['start'], phase['end'], phase['intervals']), (5, 7, 2))

    def recovery_fixture(self):
        self.args.scenario = 'capacity'
        self.args.mode = 'reliable'
        self.args.paths = 3
        self.args.rate_mbps = 10
        self.args.seconds = 20
        self.args.recovery_mbps = 25
        load = HELPERS['offered_megabits']
        records = int(load(self.args, 0, 20) * 125)
        self.tx = [{'event': 'summary', 'offered': records, 'admitted': records},
                   {'event': 'rate_change', 'time': 9.001, 'scheduled_time': 9, 'mbps': 25}]
        self.rx = []
        self.samples = []
        for t in range(2, 21):
            received = int(load(self.args, 0, t) * 125)
            interval = int(load(self.args, t-1, t) * 125)
            self.rx.append({'event': 'sample', 'time': t, 'interval_start': t-1,
                            'received': received, 'received_bytes': received * 1000,
                            'latency_histogram_ms': [[19, interval]]})
            restored = max(0, t-9) * 25 / 3
            old = min(t, 4) * 10 / 3
            healthy = max(0, min(t, 9)-4) * 5
            forward = [{'bytes': (old + restored) * 125000},
                       {'bytes': (old + healthy + restored) * 125000},
                       {'bytes': (old + healthy + restored) * 125000}]
            self.samples.append({'time': t, 'forward': forward, 'sent': copy.deepcopy(forward)})
        self.rx.append({'event': 'summary', 'received': records, 'corrupt': 0,
                        'duplicates': 0, 'outside_reorder_window': 0})
        return [{'event': 'fault', 'time': 4}, {'event': 'restore', 'time': 8.2}]

    def test_recovery_load_integral_and_path_reuse(self):
        faults = self.recovery_fixture()
        load = HELPERS['offered_megabits']
        self.assertEqual(load(self.args, 0, 20), 365)
        self.assertEqual(load(self.args, 8, 10), 35)
        self.assertEqual(load(self.args, 10, 11), 25)
        report = self.report(faults=faults)
        self.assertTrue(report['passed'], report['checks'])
        self.assertEqual(report['expected_records'], 45625)
        self.assertEqual(report['recovery']['early_application']['mbps'], 25)
        self.assertEqual(report['recovery']['sustained_application']['mbps'], 25)
        self.assertAlmostEqual(report['recovery']['early_restored_wire_mbps'], 25/3)
        self.assertLess(report['recovery']['early_application']['end'], 13.2)

    def test_recovery_requires_recorded_change_after_restore(self):
        faults = self.recovery_fixture()
        original = copy.deepcopy(self.tx)
        for changes in ([], [dict(original[1], time=8)],
                        [dict(original[1], time=14)], [dict(original[1], mbps=24)],
                        [original[1], original[1]]):
            self.tx = [original[0]] + changes
            report = self.report(faults=faults)
            self.assertFalse(report['checks']['recovery_rate_change_recorded'])
            self.assertFalse(report['checks']['recovery_goodput_within_5s'])
        self.tx = original
        self.assertFalse(self.report(faults=faults[:1])['checks']['recovery_rate_change_recorded'])

    def test_recovery_cannot_pass_with_unused_path_or_late_catch_up(self):
        faults = self.recovery_fixture()
        for row in self.samples:
            if row['time'] >= 9:
                row['forward'][0]['bytes'] = 2000000
        self.assertFalse(self.report(faults=faults)['checks']['restored_wire_use_within_5s'])
        faults = self.recovery_fixture()
        # Leave the final summary complete; no early high-load progress.
        for row in self.rx:
            if row.get('event') == 'sample' and 9 <= row['time'] <= 13:
                row['received_bytes'] = 11250000
        report = self.report(faults=faults)
        self.assertTrue(report['checks']['all_admitted_delivered'])
        self.assertFalse(report['checks']['recovery_goodput_within_5s'])
        self.args.recovery_mbps = 20
        self.assertFalse(self.report(faults=faults)['checks']['recovery_offer_requires_restored_path'])

    def test_recovery_cli_requires_meaningful_fault_load(self):
        common = ['--scenario', 'capacity', '--seconds', '120', '--warmup', '5',
                  '--fault-at', '30', '--restore-at', '90']
        for options in (['--recovery-mbps', '2000'], ['--recovery-mbps', '100001'],
                        ['--mode', 'raw-udp', '--recovery-mbps', '2300'],
                        ['--scenario', 'healthy', '--recovery-mbps', '2300'],
                        ['--seconds', '95', '--recovery-mbps', '2300']):
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                                     '--output-dir', '/unused', *common, *options],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_generator_shortfall_cannot_hide_behind_admitted_delivery(self):
        self.tx[0].update(offered=1000, admitted=1000)
        self.rx[-1]['received'] = 1000
        result = self.report()
        self.assertFalse(result['checks']['generator_kept_up'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['target_application_mbps'], 10)
        self.assertEqual(result['actual_offered_average_mbps'], .8)
        self.assertEqual(result['admitted_average_mbps'], .8)

    def test_backpressure_counts_against_offered_delivery(self):
        self.tx[0]['admitted'] = 10000
        self.rx[-1]['received'] = 10000
        result = self.report()
        self.assertTrue(result['checks']['admitted_delivery_99_9pct'])
        self.assertFalse(result['checks']['offered_delivery_99_9pct'])
        self.assertEqual(result['actual_offered_average_mbps'], 10)
        self.assertEqual(result['admitted_average_mbps'], 8)
        self.assertEqual(result['delivered_fraction_of_offered'], .8)

    def test_retries_do_not_count_as_new_offered_records(self):
        self.args.source_policy = 'retry'
        self.tx[0].update(offered=1000, admitted=1000, send_attempts=12500,
                          backpressured=11500, source_pending_records=0)
        self.rx[-1]['received'] = 1000
        result = self.report()
        self.assertEqual(result['source_policy'], 'retry')
        self.assertTrue(result['checks']['offered_delivery_99_9pct'])
        self.assertFalse(result['checks']['generator_kept_up'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['actual_offered_average_mbps'], .8)

    def test_drain_cannot_hide_steady_stall(self):
        for event in self.rx[:-1]:
            event['received_bytes'] = 1250000
        self.assertFalse(self.report()['checks']['steady_goodput_90pct_offer'])

    def test_drain_delivery_cannot_hide_missed_deadline(self):
        self.args.deadline_ms = 200
        self.tx[0].update(deadline_ms=200, source_cohorts=[dict(
            second=0, offered=12500, admitted=12500, received=0, late=0)])
        self.rx[-1].update(deadline_ms=200, received_late=25, source_cohorts=[dict(
            second=0, offered=0, admitted=0, received=12500, late=25)])
        result = self.report()
        self.assertTrue(result['checks']['offered_delivery_99_9pct'])
        self.assertTrue(result['checks']['source_cohort_accounting'])
        self.assertFalse(result['checks']['deadline_delivery_99_9pct'])
        self.assertEqual(result['deadline_delivered_fraction_of_offered'], .998)
        self.assertFalse(result['passed'])
        self.rx[-1]['deadline_ms'] = 300
        self.assertFalse(self.report()['checks']['source_cohort_accounting'])
        self.assertIsNone(self.report()['deadline_delivered_fraction_of_offered'])

    def test_fixedrate_fault_loss_is_reported_without_reliability_gate(self):
        self.args.scenario = 'capacity'
        self.rx[-1]['received'] = 12000
        # Valid avoidance evidence; the dropped records remain in the report.
        for sample in self.samples:
            sample['sent'][0]['bytes'] = min(sample['time'], 4) * 600000
        result = self.report(faults=[{'event': 'fault', 'time': 4},
                                    {'event': 'restore', 'time': 8}])
        self.assertTrue(result['passed'])
        self.assertFalse(result['qualified'])
        self.assertEqual(result['delivery_requirement'], 'best_effort_fault_loss_reported')
        self.assertEqual(result['missing_admitted_records'], 500)
        self.assertEqual(result['delivered_fraction_of_admitted'], .96)
        self.assertEqual(result['delivered_fraction_of_offered'], .96)
        self.assertNotIn('admitted_delivery_99_9pct', result['checks'])
        self.assertNotIn('offered_delivery_99_9pct', result['checks'])
        self.args.scenario = 'healthy'
        self.assertFalse(self.report()['checks']['offered_delivery_99_9pct'])

    def test_recovery_modes_require_every_admitted_record(self):
        for mode in ('reliable', 'rateless'):
            for scenario in ('healthy', 'capacity'):
                self.args.mode, self.args.scenario = mode, scenario
                self.rx[-1]['received'] = 12499  # Would pass the old 99.9% gate.
                result = self.report()
                self.assertEqual(result['delivery_requirement'], 'all_admitted_within_bounded_drain')
                self.assertFalse(result['checks']['all_admitted_delivered'])
                self.assertFalse(result['passed'])
                self.rx[-1]['received'] = 12500
                self.assertTrue(self.report()['checks']['all_admitted_delivered'])
                self.rx[-1]['received'] = 12501
                self.assertFalse(self.report()['checks']['all_admitted_delivered'])

    def test_raw_udp_keeps_delivery_gate_for_calibration(self):
        self.args.mode, self.args.scenario = 'raw-udp', 'calibration'
        self.rx[-1]['received'] = 12000
        self.assertFalse(self.report()['checks']['offered_delivery_99_9pct'])

    def test_cohorts_reconcile_missing_and_late_records_by_submission_time(self):
        tx = dict(offered=20, admitted=20, source_cohorts=[
            dict(second=s, offered=10, admitted=10, received=0, late=0) for s in (0, 1)])
        rx = dict(received=18, received_late=2, source_cohorts=[
            dict(second=0, offered=0, admitted=0, received=8, late=2),
            dict(second=1, offered=0, admitted=0, received=10, late=0)])
        rows, complete = HELPERS['delivery_cohorts'](tx, rx)
        self.assertTrue(complete)
        self.assertEqual(rows[0]['missing_admitted'], 2)
        self.assertEqual(rows[0]['received_in_time'], 6)
        self.assertEqual(rows[1]['missing_admitted'], 0)
        for mutation in ('total', 'duplicate', 'unknown_second', 'late'):
            bad = copy.deepcopy(rx)
            if mutation == 'total':
                bad['received'] += 1
            elif mutation == 'duplicate':
                bad['source_cohorts'].append(bad['source_cohorts'][0])
            elif mutation == 'unknown_second':
                bad['source_cohorts'][0]['second'] = 5
            else:
                bad['source_cohorts'][0]['late'] = 9
                bad['received_late'] = 9
            self.assertFalse(HELPERS['delivery_cohorts'](tx, bad)[1])

    def test_requested_deadline_requires_cohort_evidence(self):
        self.args.deadline_ms = 200
        self.assertFalse(self.report()['checks']['source_cohort_accounting'])
        self.assertFalse(self.report()['checks']['deadline_delivery_99_9pct'])

    def test_missing_summary_and_failed_endpoint_fail(self):
        self.rx.pop()
        self.assertFalse(self.report()['passed'])
        self.assertFalse(self.report(exits=[0, 1])['checks']['endpoints_completed'])

    def test_calibration_requires_absolute_headroom(self):
        self.args.scenario = 'calibration'
        self.args.calibration_wire_mbps = 2880
        self.assertFalse(self.report()['checks']['fixture_wire_headroom'])

    def test_corruption_duplicates_and_too_old_records_fail(self):
        original = copy.deepcopy(self.rx)
        for key in ('corrupt', 'duplicates', 'outside_reorder_window'):
            self.rx = copy.deepcopy(original)
            self.rx[-1][key] = 1
            self.assertFalse(self.report()['checks']['integrity_and_deduplication'])

    def test_fault_requires_evidence_and_reaction(self):
        self.args.scenario = 'capacity'
        self.assertFalse(self.report()['checks']['fault_applied_and_restored'])
        result = self.report(faults=[{'event': 'fault', 'time': 4.1}, {'event': 'restore', 'time': 8.1}])
        self.assertTrue(result['checks']['fault_path_exercised'])
        self.assertFalse(result['checks']['degraded_sent_wire_share_below_10pct'])

    def test_rate_cap_alone_does_not_prove_avoidance(self):
        self.args.scenario = 'capacity'
        for sample in self.samples:
            if sample['time'] >= 5:
                sample['forward'][0]['bytes'] = 4*600000
        result = self.report(faults=[{'event': 'fault', 'time': 4.1}, {'event': 'restore', 'time': 8.1}])
        self.assertFalse(result['checks']['degraded_sent_wire_share_below_10pct'])

    def test_invalid_load_arguments_rejected_before_network_setup(self):
        binary = ROOT / 'examples/transit_benchmark'
        if not binary.exists():
            self.skipTest('build examples/transit_benchmark for CLI checks')
        for arg in ('nan', 'inf', '-1', '0'):
            result = subprocess.run([str(binary), '--mbps', arg], capture_output=True)
            self.assertEqual(result.returncode, 2)
        result = subprocess.run([str(binary), '--source-policy', 'unknown'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        for arg in ('0', 'nan', '60001'):
            result = subprocess.run([str(binary), '--deadline-ms', arg], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_raw_udp_cannot_silently_ignore_retry_policy(self):
        result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
            '--mode', 'raw-udp', '--source-policy', 'retry', '--output-dir', 'unused'],
            capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'requires a qlinq delivery mode', result.stderr)

    def test_current_endpoint_limits_reject_invalid_counts(self):
        for options in (['--total-stream-egress-bytes', '0'],
                        ['--stream-egress-bytes', '-1'],
                        ['--receive-memory-bytes', '0'],
                        ['--recovery-cache-bytes', '-1'],
                        ['--egress-packets', 'nan'],
                        ['--egress-bytes', '0'],
                        ['--packets-per-service', '-1'],
                        ['--send-batch', '0'],
                        ['--send-batch', '4097']):
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                                     '--output-dir', '/unused', *options],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_endpoint_limits_pass_through_without_changing_defaults(self):
        self.assertEqual(HELPERS['endpoint_limit_arguments'](SimpleNamespace()), [])
        options = SimpleNamespace(repair_requests_per_second=1024,
            aggregate_repair_requests_per_second=2048,
            aggregate_nack_requests_per_second=512,
            stream_egress_bytes=33554432, receive_memory_bytes=67108864,
            recovery_cache_bytes=33554432, egress_packets=4096,
            egress_bytes=33554432, packets_per_service=4096,
            event_queue_events=8192, event_queue_bytes=134217728)
        self.assertEqual(HELPERS['endpoint_limit_arguments'](options), [
            '--stream-egress-bytes', '33554432',
            '--receive-memory-bytes', '67108864',
            '--recovery-cache-bytes', '33554432',
            '--egress-packets', '4096', '--egress-bytes', '33554432',
            '--packets-per-service', '4096', '--event-queue-events', '8192',
            '--event-queue-bytes', '134217728',
            '--repair-requests-per-second', '1024',
            '--aggregate-repair-requests-per-second', '2048',
            '--aggregate-nack-requests-per-second', '512'])

    def test_repair_budget_arguments_reject_invalid_or_ignored_values(self):
        for option in ('--repair-requests-per-second', '--aggregate-repair-requests-per-second',
                       '--aggregate-nack-requests-per-second'):
            for value in ('0', '-1', '65536', '1.5', 'nan'):
                result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                    option, value, '--output-dir', '/unused'], capture_output=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                binary = ROOT / 'examples/transit_benchmark'
                if binary.exists():
                    result = subprocess.run([str(binary), option, value], capture_output=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                option, '1024', '--mode', 'raw-udp', '--output-dir', '/unused'], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'repair request limits require a qlinq delivery mode', result.stderr)

    def test_router_cpu_pairs_follow_path_order(self):
        pairs = HELPERS['router_cpus']('2,3,4,5,6,7')
        self.assertEqual([HELPERS['router_cpu_pair'](pairs, i) for i in range(3)],
                         [(2, 3), (4, 5), (6, 7)])
        self.assertEqual([HELPERS['router_cpu_pair']((2, 3), i) for i in range(3)],
                         [(2, 3)] * 3)

    def test_router_cpu_path_count_fails_before_setup(self):
        for paths, cpus in ((3, '2,3,4,5'), (2, '2,3,4,5,6,7'), (1, '2,3,4,5')):
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                '--paths', str(paths), '--router-cpus', cpus,
                '--output-dir', '/unused'], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'exactly one pair per configured path', result.stderr)

    def test_invalid_router_cpu_pair_fails_before_setup(self):
        for value in ('2', '2,3,4', '-1,3', 'a,3'):
            result = subprocess.run([str(ROOT / 'examples/multipath_transit_demo'),
                '--router-cpus='+value, '--output-dir', 'unused'], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'forward,reverse CPU indices', result.stderr)


class ReplayTests(unittest.TestCase):
    def fixture(self, directory):
        case = ReportTests()
        case.setUp()
        path = Path(directory)
        (path / 'metadata.json').write_text(json.dumps({'arguments': vars(case.args)}))
        for filename, rows in [('send.jsonl', case.tx), ('receive.jsonl', case.rx)]:
            (path / filename).write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (path / 'queues.json').write_text(json.dumps(case.samples))
        (path / 'faults.json').write_text('[]')
        return case, path

    def test_live_and_replay_have_identical_reports(self):
        from transit_replay import replay
        with tempfile.TemporaryDirectory() as directory:
            case, path = self.fixture(directory)
            (path / 'endpoint-exits.json').write_text('[0, 0]')
            self.assertEqual(replay(path), case.report())
            (path / 'endpoint-exits.json').write_text('[0, 1]')
            self.assertEqual(replay(path), case.report(exits=[0, 1]))
            self.assertFalse(replay(path)['passed'])

    def test_missing_trial_arguments_are_a_clear_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            _, path = self.fixture(directory)
            (path / 'metadata.json').write_text('{"arguments": {}}')
            result = subprocess.run(['python3', str(Path(__file__).parent / 'transit_replay.py'),
                                     str(path), '--exits', '0', '0'],
                                    capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'error:', result.stderr)
            self.assertNotIn(b'Traceback', result.stderr)

    def test_legacy_process_result_and_missing_evidence(self):
        from transit_replay import replay
        with tempfile.TemporaryDirectory() as directory:
            case, path = self.fixture(directory)
            with self.assertRaises(FileNotFoundError):
                replay(path)
            self.assertEqual(replay(path, [0, 0]), case.report())
            (path / 'report.json').write_text(json.dumps(case.report()))
            self.assertEqual(replay(path), case.report())
            (path / 'endpoint-exits.json').write_text('[true, 0]')
            with self.assertRaises(ValueError):
                replay(path)


if __name__ == '__main__':
    unittest.main()
