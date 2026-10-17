#!/usr/bin/env python3
"""Checks that bandwidth-demo validation rejects misleading success reports."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

demo = runpy.run_path(str(Path(__file__).with_name('multipath_bw_demo')))


def analyze(output, samples, exit_code):
    return demo['analyze'](output, samples, exit_code,
                           demo['DEFAULT_OFFERED_MBPS'],
                           demo['DEFAULT_INITIAL_MBPS'])


class BandwidthReportTests(unittest.TestCase):
    def fixture(self):
        rates = tuple(cap * 0.6 for cap in demo['RATES'])
        output = ''.join(f'path {i}: rate={rate * 1e6 / 8:.0f} B/s share={rate / sum(rates) * 100:.1f}%\n'
                         for i, rate in enumerate(rates))
        output += ('window_offered: 1500\nwindow_admitted: 1500\nwindow_received: 1500\n'
                   f"window_goodput_mbps: {demo['DEFAULT_OFFERED_MBPS']}\nwindow_p99_latency_ms: 50\n")
        samples = [{'time': 4.5 + i * 0.25,
                    'queues': {f'1:{n}2': {'bytes': int(rate * i * 0.25 * 1e6 / 8),
                                           'packets': i, 'drops': 0,
                                           'backlog': demo['RATES'][n - 1] * 2500}
                               for n, rate in enumerate(rates, 1)}}
                   for i in range(29)]
        return output, samples

    def test_healthy_aggregation(self):
        output, samples = self.fixture()
        self.assertTrue(analyze(output, samples, 0)['passed'])

    def test_datagram_report_records_profile(self):
        output, samples = self.fixture()
        report = analyze('mode: datagram\n' + output, samples, 0)
        self.assertEqual(report['delivery_mode'], 'datagram')
        self.assertEqual(report['udp_payload_size'], 1452)
        self.assertEqual(report['link_mtu'], 1500)
        self.assertTrue(report['passed'])

    def test_two_gigabit_goodput_threshold(self):
        self.assertEqual(demo['DEFAULT_OFFERED_MBPS'], 2000)
        output, samples = self.fixture()
        for goodput, expected in ((1980, True), (1979.99, False)):
            with self.subTest(goodput=goodput):
                measured = output.replace('window_goodput_mbps: 2000.0',
                                          f'window_goodput_mbps: {goodput}')
                self.assertEqual(analyze(measured, samples, 0)['passed'], expected)

    def test_missing_measurements_cannot_pass(self):
        output, samples = self.fixture()
        self.assertFalse(analyze('', samples, 0)['passed'])
        self.assertFalse(analyze(output, [], 0)['passed'])
        del samples[10]['queues']['1:12']
        self.assertFalse(analyze(output, samples, 0)['checks']['measurement_available'])

    def test_backpressure_is_delivery_failure(self):
        output, samples = self.fixture()
        output = output.replace('window_admitted: 1500', 'window_admitted: 1000')
        output = output.replace('window_received: 1500', 'window_received: 1000')
        self.assertFalse(analyze(output, samples, 0)['checks']['delivery_at_least_99pct'])

    def test_growing_queue_and_drops_fail(self):
        output, samples = self.fixture()
        for i, sample in enumerate(samples):
            sample['queues']['1:12']['backlog'] += i * demo['RATES'][0] * 2500
            sample['queues']['1:12']['drops'] = i
        checks = analyze(output, samples, 0)['checks']
        self.assertFalse(checks['queues_bounded'])
        self.assertFalse(checks['no_steady_queue_drops'])

    def test_broken_cap_or_preference_fails(self):
        output, samples = self.fixture()
        for sample in samples:
            sample['queues']['1:12']['bytes'] *= 10
        checks = analyze(output, samples, 0)['checks']
        self.assertFalse(checks['caps_respected'])
        self.assertFalse(checks['traffic_matches_capabilities'])

    def test_low_goodput_and_high_latency_fail(self):
        output, samples = self.fixture()
        output = output.replace(
            f"window_goodput_mbps: {demo['DEFAULT_OFFERED_MBPS']}",
            f"window_goodput_mbps: {demo['DEFAULT_OFFERED_MBPS'] * 0.98}")
        output = output.replace('window_p99_latency_ms: 50',
                                'window_p99_latency_ms: 251')
        checks = analyze(output, samples, 0)['checks']
        self.assertFalse(checks['sustains_configured_offer'])
        self.assertFalse(checks['p99_at_most_250ms'])

    def test_failed_benchmark_cannot_pass(self):
        output, samples = self.fixture()
        self.assertFalse(analyze(output, samples, 1)['passed'])

    def fixed_fixture(self):
        rates = (1250, 2500, 5000)
        output = ''.join(f'path {i}: rate={cap * .6 * 1e6 / 8:.0f} B/s share={cap / sum(rates) * 100:.1f}%\n'
                         for i, cap in enumerate(rates))
        output += ('window_offered: 625000\nwindow_admitted: 625000\nwindow_received: 625000\n'
                   'window_attempted_in_interval: 625000\nwindow_goodput_mbps: 5000\n'
                   'window_p99_latency_ms: 50\nwindow_duration_ms: 8000\n'
                   'window_start_monotonic_ms: 104000\nwindow_end_monotonic_ms: 112000\n'
                   'latency_origin: scheduled\n')
        # queue alignment uses monotonic source origin
        samples = [{'time': 100 + i * .25, 'monotonic_ms': 104500 + i * 250,
                    'queues': {f'1:{n}2': {'bytes': int(cap * .6 * i * .25 * 1e6 / 8),
                                           'packets': i, 'drops': 0, 'backlog': cap * 2500}
                               for n, cap in enumerate(rates, 1)}} for i in range(29)]
        return output, samples, rates

    def fixed_analyze(self, output, samples, rates):
        return demo['analyze'](output, samples, 0, 5000, 250, rates, require_fixed=True)

    def test_fixed_five_gigabit_uses_monotonic_queue_interval(self):
        output, samples, rates = self.fixed_fixture()
        report = self.fixed_analyze(output, samples, rates)
        self.assertTrue(report['passed'])
        self.assertTrue(report['fixed_wall_clock'])
        self.assertEqual(report['latency_origin'], 'scheduled')

    def test_stretched_fixed_window_cannot_pass(self):
        output, samples, rates = self.fixed_fixture()
        output = output.replace('window_end_monotonic_ms: 112000',
                                'window_end_monotonic_ms: 117000')
        output = output.replace('window_duration_ms: 8000', 'window_duration_ms: 13000')
        checks = self.fixed_analyze(output, samples, rates)['checks']
        self.assertFalse(checks['fixed_measurement_interval'])

    def test_unattempted_records_cannot_disappear_from_source(self):
        output, samples, rates = self.fixed_fixture()
        output = output.replace('window_offered: 625000', 'window_offered: 300000')
        output = output.replace('window_received: 625000', 'window_received: 300000')
        output = output.replace('window_attempted_in_interval: 625000',
                                'window_attempted_in_interval: 300000')
        checks = self.fixed_analyze(output, samples, rates)['checks']
        self.assertTrue(checks['delivery_at_least_99pct'])
        self.assertFalse(checks['scheduled_source_accounted'])
        self.assertFalse(checks['source_kept_up'])

    def test_late_or_unattempted_source_records_fail_rate_gate(self):
        output, samples, rates = self.fixed_fixture()
        for attempted, expected in ((618750, True), (618749, False), (625001, False)):
            with self.subTest(attempted=attempted):
                measured = output.replace('window_attempted_in_interval: 625000',
                                          f'window_attempted_in_interval: {attempted}')
                self.assertEqual(self.fixed_analyze(measured, samples, rates)['checks']['source_kept_up'], expected)

    def test_fixed_latency_must_include_source_lateness(self):
        output, samples, rates = self.fixed_fixture()
        output = output.replace('latency_origin: scheduled', 'latency_origin: submitted')
        self.assertFalse(self.fixed_analyze(output, samples, rates)['checks']['fixed_measurement_interval'])

    def test_legacy_executable_cannot_pass_fixed_qualification(self):
        output, samples = self.fixture()
        report = demo['analyze'](output, samples, 0, 2000, 250, require_fixed=True)
        self.assertFalse(report['passed'])
        self.assertFalse(report['checks']['fixed_measurement_interval'])


class BandwidthNamespaceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='qlinq-bw-test-')
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name)

    def run_all_modes(self, exit_codes):
        with mock.patch.object(demo['sys'], 'argv',
                               ['multipath_bw_demo', '--all-modes',
                                '--output-dir', str(self.output)]), \
             mock.patch.object(demo['shutil'], 'which', return_value='/test/tool'), \
             mock.patch.object(demo['os'], 'chdir'), \
             mock.patch.object(demo['subprocess'], 'run') as build, \
             mock.patch.object(demo['subprocess'], 'call', side_effect=exit_codes) as run, \
             redirect_stdout(io.StringIO()):
            result = demo['main']()
        build.assert_called_once_with(
            ['make', 'examples/data_multipath_benchmark', 'gencerts'], check=True)
        self.assertEqual(len(run.call_args_list), len(demo['DELIVERY_MODES']))
        for mode, call in zip(demo['DELIVERY_MODES'], run.call_args_list):
            argv = call.args[0]
            self.assertEqual(argv[:2], ['unshare', '-Urn'])
            self.assertIn('--in-namespace', argv)
            self.assertIn('--' + mode, argv)
            self.assertNotIn('--all-modes', argv)
            self.assertEqual(argv[argv.index('--output-dir') + 1],
                             str(self.output / mode))
            self.assertTrue((self.output / mode).is_dir())
            self.assertIn('QLINQ_BW_PARENT_NETNS', call.kwargs['env'])
        return result, json.loads((self.output / 'report.json').read_text())

    def test_all_modes_aggregate_success(self):
        result, report = self.run_all_modes([0, 0, 0, 0])
        self.assertEqual(result, 0)
        self.assertTrue(report['passed'])
        self.assertEqual(tuple(report['modes']), demo['DELIVERY_MODES'])
        for mode, result in report['modes'].items():
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['report_path'], str(self.output / mode / 'report.json'))

    def test_all_modes_continue_after_failure(self):
        result, report = self.run_all_modes([1, 0, 2, 0])
        self.assertEqual(result, 1)
        self.assertFalse(report['passed'])
        self.assertEqual([mode['exit_code'] for mode in report['modes'].values()],
                         [1, 0, 2, 0])

    def test_delivery_flags_are_mutually_exclusive(self):
        for flags in (['--all-modes', '--reliable'], ['--datagram', '--fixed-fec']):
            with self.subTest(flags=flags), \
                 mock.patch.object(demo['sys'], 'argv', ['multipath_bw_demo', *flags]), \
                 redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit) as error:
                demo['main']()
            self.assertEqual(error.exception.code, 2)

    def test_single_mode_preserves_options_and_exit_status(self):
        args = SimpleNamespace(output_dir=str(self.output), benchmark='/tmp/benchmark',
                               offered_mbps=1500, initial_mbps=100,
                               delivery_mode='reliable', single_path=True)
        with mock.patch.object(demo['subprocess'], 'call', return_value=3) as run:
            self.assertEqual(demo['run_namespaces'](args), 3)
        run.assert_called_once()
        argv = run.call_args.args[0]
        for option, value in (('--output-dir', str(self.output)),
                              ('--benchmark', '/tmp/benchmark'),
                              ('--offered-mbps', '1500'), ('--initial-mbps', '100')):
            self.assertEqual(argv[argv.index(option) + 1], value)
        self.assertIn('--single-path', argv)
        self.assertIn('--reliable', argv)

    def test_links_use_explicit_mtu(self):
        with mock.patch.dict(demo['setup_links'].__globals__, command=mock.Mock()) as state:
            command = state['command']
            demo['setup_links']()
        for n in range(1, len(demo['RATES']) + 1):
            for interface in (f'bw{n}', f'bw{n}_peer'):
                command.assert_any_call('ip', 'link', 'set', interface,
                                        'mtu', '1500', 'up')

    def test_benchmark_receives_bounded_udp_payload(self):
        args = SimpleNamespace(output_dir=str(self.output), benchmark=None,
                               offered_mbps=2000, initial_mbps=250,
                               delivery_mode='datagram')
        proc = mock.Mock(returncode=0)
        proc.poll.return_value = 0
        with mock.patch.dict(demo['run'].__globals__, setup_links=mock.Mock()), \
             mock.patch.object(demo['subprocess'], 'Popen', return_value=proc) as run, \
             redirect_stdout(io.StringIO()):
            demo['run'](args)
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index('--udp-payload-size') + 1], '1452')
        self.assertIn('--datagram', argv)

    def test_five_gigabit_profile_scales_capacity_and_propagation_storage(self):
        args = SimpleNamespace(offered_mbps=5000, single_path=False)
        self.assertEqual(demo['profile'](args), ((1250, 2500, 5000), 10240))
        args.single_path = True
        self.assertEqual(demo['profile'](args), ((5000,), 10240))

    def test_five_gigabit_command_preserves_all_controls(self):
        args = SimpleNamespace(output_dir=str(self.output), benchmark=None,
                               offered_mbps=5000, initial_mbps=250,
                               delivery_mode='reliable', congestion_control='cubic',
                               pacing='on', abba='on', cipher='aes128gcm', source_batch=8)
        proc = mock.Mock(returncode=0)
        proc.poll.return_value = 0
        with mock.patch.dict(demo['run'].__globals__, setup_links=mock.Mock()), \
             mock.patch.object(demo['subprocess'], 'Popen', return_value=proc) as run, \
             redirect_stdout(io.StringIO()):
            demo['run'](args)
        argv = run.call_args.args[0]
        for option, value in (('--duration-ms', '12000'), ('--packets', '789063'),
                              ('--fps', '78125.0'), ('--source-batch', '8'),
                              ('--congestion-control', 'cubic'), ('--pacing', 'on'),
                              ('--abba', 'on'), ('--cipher', 'aes128gcm')):
            self.assertEqual(argv[argv.index(option) + 1], value)

    def test_profile_and_controls_propagate_to_namespace(self):
        args = SimpleNamespace(output_dir=str(self.output), benchmark=None,
                               offered_mbps=5000, initial_mbps=250,
                               delivery_mode='reliable', single_path=False, profile='5g',
                               path_rates_mbps=(1000, 3000, 6000), queue_packets=12000,
                               congestion_control='cubic', pacing='on', abba='on',
                               cipher='aes256gcm', source_batch=4)
        with mock.patch.object(demo['subprocess'], 'call', return_value=0) as run:
            demo['run_namespaces'](args)
        argv = run.call_args.args[0]
        for option, value in (('--profile', '5g'), ('--queue-packets', '12000'),
                              ('--abba', 'on'), ('--cipher', 'aes256gcm')):
            self.assertEqual(argv[argv.index(option) + 1], value)
        at = argv.index('--path-rates-mbps')
        self.assertEqual(argv[at + 1:at + 4], ['1000', '3000', '6000'])

    def test_invalid_or_unbounded_profiles_fail_before_build(self):
        for flags in (['--offered-mbps', 'nan'], ['--offered-mbps', '7000'],
                      ['--source-batch', '0'], ['--queue-packets', '65537'],
                      ['--path-rates-mbps', '1000', '900', '2000'], ['--abba', 'on']):
            with self.subTest(flags=flags), \
                 mock.patch.object(demo['sys'], 'argv', ['multipath_bw_demo', *flags]), \
                 mock.patch.object(demo['subprocess'], 'run') as build, \
                 redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit) as error:
                demo['main']()
            self.assertEqual(error.exception.code, 2)
            build.assert_not_called()


if __name__ == '__main__':
    unittest.main()
