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


if __name__ == '__main__':
    unittest.main()
