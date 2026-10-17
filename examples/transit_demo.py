"""Separate-process transit qualification fixture (Linux, isolated namespaces).

Application Mbps is explicit. Router byte counters measure the resulting wire
load, including FEC overhead. A successful smoke test is not gigabit qualification.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from transit_fixture import (DISABLED_OFFLOADS, Topology, apply_path_fault, command,
                             cpu_mask, netem_seed, parse_offloads, parse_snmp,
                             router_cpu_pair, router_cpus)
from transit_report import (analyze, delivery_cohorts, events, fault_directions,
                           fault_reaction_seconds, latency_window, offered_megabits,
                           path_profile, wire_fraction)

ROOT = Path(__file__).resolve().parents[1]


def git_identity(directory):
    """Do not attribute an unversioned experiment copy to its parent checkout."""
    directory = Path(directory).resolve()
    try:
        top = Path(command('git', '-C', directory, 'rev-parse', '--show-toplevel').strip()).resolve()
        if top != directory:
            return None
        return {'commit': command('git', '-C', directory, 'rev-parse', 'HEAD').strip(),
                'tracked_diff_sha256': hashlib.sha256(
                    command('git', '-C', directory, 'diff', 'HEAD', '--binary').encode()).hexdigest()}
    except (OSError, subprocess.CalledProcessError):
        return None



LIMIT_OPTIONS = (
    ('stream-egress-bytes', None, 4294967295, 'explicit per-stream retained-byte cap; default 2 MiB'),
    ('total-stream-egress-bytes', None, 4294967295, 'explicit endpoint retained-byte cap; default 16 MiB including control reserve'),
    ('receive-memory-bytes', None, 4294967295, 'explicit receive assembly-memory cap; default 64 MiB'),
    ('recovery-cache-bytes', None, 4294967295, 'explicit retained recovery-payload cap; default 32 MiB'),
    ('egress-packets', None, 4294967295, 'explicit per-socket queued-packet cap; default 1024'),
    ('egress-bytes', None, 4294967295, 'explicit per-socket queued-byte cap; default 4 MiB'),
    ('packets-per-service', None, 4294967295, 'explicit maximum packets processed per service call; default 2048'),
    ('event-queue-events', 8192, 4294967295, 'maximum queued public record events per endpoint; default 8192'),
    ('event-queue-bytes', 134217728, 4294967295, 'maximum bytes retained by queued public events; default 128 MiB'),
    ('repair-requests-per-second', None, 65535, 'per-peer repair request budget; transport default 16'),
    ('aggregate-repair-requests-per-second', None, 65535, 'endpoint repair response budget; transport default 256'),
    ('aggregate-nack-requests-per-second', None, 65535, 'endpoint recovery feedback budget; transport default 16'),
)


def endpoint_limit_arguments(args):
    result = []
    for option, _, _, _ in LIMIT_OPTIONS:
        value = getattr(args, option.replace('-', '_'), None)
        if value is not None:
            result += ['--' + option, str(value)]
    return result


def run(args):
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    start_file = out / 'start.ns'
    if start_file.exists():
        start_file.unlink()
    topo = Topology()
    procs, logs = [], []
    samples, faults = [], []
    shaped = args.scenario != 'calibration'
    try:
        tx, rx = topo.namespace(), topo.namespace()
        network_before = {role: parse_snmp(topo.cmd(pid, 'cat', '/proc/net/snmp'))
                          for pid, role in ((tx, 'send'), (rx, 'receive'))}
        routers, forward, reverse, sender_devices, receiver_devices = [], [], [], [], []
        for pid in (tx, rx):
            topo.cmd(pid, 'ip', 'link', 'set', 'lo', 'up')
        for i in range(args.paths):
            n = i+1
            router = topo.namespace()
            routers.append(router)
            topo.cmd(router, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
            sdev, back = topo.pair(tx, router, f's{n}', f'10.60.{n}.1', f'10.60.{n}.2')
            sender_devices.append(sdev)
            rdev, ahead = topo.pair(rx, router, f'r{n}', f'10.61.{n}.1', f'10.61.{n}.2')
            forward.append(ahead)
            reverse.append(back)
            receiver_devices.append(rdev)
            if args.router_cpus is not None:
                mountpoint = out / 'rps-sys'
                mountpoint.mkdir(exist_ok=True)
                forward_cpu, reverse_cpu = router_cpu_pair(args.router_cpus, i)
                topo.steer_receive(router, back, forward_cpu, mountpoint)
                topo.steer_receive(router, ahead, reverse_cpu, mountpoint)
            topo.cmd(tx, 'ip', 'route', 'add', f'10.61.{n}.0/30', 'via', f'10.60.{n}.2', 'dev', sdev)
            topo.cmd(rx, 'ip', 'route', 'add', f'10.60.{n}.0/30', 'via', f'10.61.{n}.2', 'dev', rdev)
            if shaped:
                for direction, dev in (('reverse', back), ('forward', ahead)):
                    topo.shape(router, dev, *path_profile(args, i), seed=netem_seed(args, i, direction))
        binary = str(ROOT / ('examples/transit_udp_calibration' if args.mode == 'raw-udp' else 'examples/transit_benchmark'))
        common = ['--start-file', str(start_file), '--mode', args.mode,
                  '--seconds', str(args.seconds), '--drain', str(args.drain),
                  '--mbps', str(args.mbps), '--record-bytes', str(args.record_bytes)]
        if args.mode != 'raw-udp':
            common += ['--source-policy', args.source_policy, '--deadline-ms', str(args.deadline_ms)]
            common += ['--congestion-control', args.congestion_control, '--pacing', args.pacing]
            common += ['--service-wait-ms', str(args.service_wait_ms)]
            if args.send_batch is not None:
                common += ['--send-batch', str(args.send_batch)]
            if args.recovery_mbps is not None:
                common += ['--step-at', str(args.restore_at + 1), '--step-mbps', str(args.recovery_mbps)]
            common += endpoint_limit_arguments(args)
        for pid, role, subnet in ((tx, 'send', 60), (rx, 'receive', 61)):
            cpu = args.sender_cpu if role == 'send' else args.receiver_cpu
            affinity = ['taskset', '-c', str(cpu)] if cpu is not None else []
            argv = topo.prefix(pid) + affinity + [binary, '--role', role] + common
            for n in range(1, args.paths+1):
                argv += ['--bind', f'10.{subnet}.{n}.1']
                if role == 'receive':
                    argv += ['--remote', f'10.60.{n}.1']
            if role == 'receive':
                argv += ['--receive-objects', str(args.receive_objects)]
                if args.mode != 'raw-udp':
                    argv += ['--receive-delivery', args.receive_delivery]
            log = (out / f'{role}.jsonl').open('w')
            logs.append(log)
            procs.append(subprocess.Popen(argv, stdout=log, stderr=log, cwd=ROOT))
        deadline = time.monotonic()+25
        paths = [out / 'send.jsonl', out / 'receive.jsonl']
        while not all(any(e.get('event') == 'ready' for e in events(p)) for p in paths):
            if time.monotonic() > deadline or any(p.poll() is not None for p in procs):
                raise RuntimeError('endpoints did not validate all paths; inspect endpoint logs')
            time.sleep(.05)
        start = time.monotonic_ns()+500_000_000
        temp = out / 'start.pending'
        temp.write_text(str(start)+'\n')
        temp.replace(start_file)
        print(f'Started {args.paths} paths; offer={args.mbps:g} application Mbps, scenario={args.scenario}', flush=True)
        faulted = restored = False
        while any(p.poll() is None for p in procs):
            elapsed = (time.monotonic_ns()-start)/1e9
            if elapsed > args.seconds+args.drain+5:
                raise RuntimeError('endpoint completion timeout')
            if shaped and args.scenario != 'healthy' and elapsed >= args.fault_at and not faulted:
                began = (time.monotonic_ns()-start)/1e9
                apply_path_fault(topo, args, routers, forward, reverse, True)
                faults.append({'event': 'fault', 'started_at': began, 'time': (time.monotonic_ns()-start)/1e9,
                               'direction': args.fault_direction})
                faulted = True
            if faulted and not restored and elapsed >= args.restore_at:
                began = (time.monotonic_ns()-start)/1e9
                apply_path_fault(topo, args, routers, forward, reverse, False)
                faults.append({'event': 'restore', 'started_at': began, 'time': (time.monotonic_ns()-start)/1e9,
                               'direction': args.fault_direction})
                restored = True
            if elapsed >= 0:
                links = json.loads(topo.cmd(tx, 'ip', '-j', '-s', 'link', 'show'))
                injected = {row['ifname']: row.get('stats64', row.get('stats'))['tx'] for row in links}
                reverse_injected = []
                if args.fault_direction != 'forward':
                    links = json.loads(topo.cmd(rx, 'ip', '-j', '-s', 'link', 'show'))
                    reverse_stats = {row['ifname']: row.get('stats64', row.get('stats'))['tx'] for row in links}
                    reverse_injected = [reverse_stats[d] for d in receiver_devices]
                samples.append({'time': (time.monotonic_ns()-start)/1e9,
                                'reverse_sent': reverse_injected,
                                'sent': [injected[d] for d in sender_devices],
                                'forward': [topo.counters(p, d, shaped) for p, d in zip(routers, forward)]})
            time.sleep(.25)
        network_after = {role: parse_snmp(topo.cmd(pid, 'cat', '/proc/net/snmp'))
                         for pid, role in ((tx, 'send'), (rx, 'receive'))}
        (out / 'network-counters.json').write_text(json.dumps(
            {'before': network_before, 'after': network_after}, indent=2)+'\n')
        for log in logs:
            log.flush()
        exits = [p.returncode for p in procs]
        (out / 'endpoint-exits.json').write_text(json.dumps(exits) + '\n')
        report = analyze(events(paths[0]), events(paths[1]), samples, args, exits, faults)
        (out / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({k: v for k, v in report.items() if k not in ('sender', 'receiver', 'path_rates', 'delivery_by_source_second')}, indent=2))
        print(f'Results: {out}')
        return 0 if report['passed'] else 1
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
        for log in logs:
            log.close()
        (out / 'queues.json').write_text(json.dumps(samples, indent=2)+'\n')
        (out / 'faults.json').write_text(json.dumps(faults, indent=2)+'\n')
        (out / 'offloads.json').write_text(json.dumps(topo.offloads, indent=2)+'\n')
        (out / 'rps.json').write_text(json.dumps(topo.rps, indent=2)+'\n')
        topo.close()



def positive(text):
    n = float(text)
    if not math.isfinite(n) or n <= 0:
        raise argparse.ArgumentTypeError('must be finite and positive')
    return n



def positive_list(text):
    try:
        return [positive(value) for value in text.split(',')]
    except (ValueError, argparse.ArgumentTypeError) as exc:
        raise argparse.ArgumentTypeError('require comma-separated finite positive values') from exc



def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scenario', choices=['calibration', 'healthy', 'capacity', 'delay', 'loss', 'outage'], default='healthy')
    p.add_argument('--paths', type=int, choices=range(1, 5), default=3)
    p.add_argument('--rate-mbps', type=positive, default=1000)
    p.add_argument('--rtt-ms', type=positive, default=40)
    p.add_argument('--path-rates-mbps', type=positive_list, metavar='R0,R1,...',
                   help='per-path caps, overriding rate-mbps; one value per path')
    p.add_argument('--path-rtts-ms', type=positive_list, metavar='RTT0,RTT1,...',
                   help='per-path RTTs, overriding rtt-ms; one value per path')
    p.add_argument('--mbps', type=positive, default=1200, help='target APPLICATION Mbps, excluding wire overhead; actual offer is reported separately')
    p.add_argument('--recovery-mbps', type=positive,
                   help='raise application offer one second after scheduled restoration; 90%% must exceed all other paths combined')
    p.add_argument('--recovery-restored-path-min-mbps', type=positive,
                   help='explicit restored-path wire-use requirement for a reduced-rate recovery diagnostic')
    p.add_argument('--seconds', type=positive, default=90)
    p.add_argument('--warmup', type=positive, default=10)
    p.add_argument('--drain', type=positive, default=5)
    p.add_argument('--deadline-ms', type=positive, default=200,
                   help='qlinq record delivery deadline from first submission; default 200 ms')
    p.add_argument('--record-bytes', type=int, choices=range(32, 16001), default=None, metavar='32..16000',
                   help='application record bytes; default 8000, or 1250 UDP payload bytes for raw-udp')
    p.add_argument('--receive-objects', type=int, choices=range(1, 1025), default=1024, metavar='1..1024',
                   help='receive-object limit; default and maximum: 1024; payload memory is separately bounded')
    p.add_argument('--mode', choices=['fixed-fec', 'rateless', 'reliable', 'raw-udp'], default='fixed-fec')
    p.add_argument('--receive-delivery', choices=['queue', 'callback'], default='queue',
                   help='receiver record bridge: queue copies owned events; callback borrows records during service')
    p.add_argument('--congestion-control', choices=['default', 'reno', 'pico', 'cubic'], default='default')
    p.add_argument('--pacing', choices=['default', 'off', 'on'], default='default')
    p.add_argument('--service-wait-ms', type=int, choices=range(0, 1001), default=1,
                   help='maximum qlinq_service poll wait per endpoint loop; default 1 ms')
    p.add_argument('--send-batch', type=int, choices=range(1, 4097),
                   help='maximum records submitted after each service call; benchmark default 32')
    for option, default, maximum, description in LIMIT_OPTIONS:
        extra = {'metavar': '1..65535'} if maximum == 65535 else {}
        p.add_argument('--' + option, type=int, default=default, help=description, **extra)
    p.add_argument('--source-policy', choices=['discard', 'retry'], default='discard',
                   help='discard rejected records, or retain one record and retry after service')
    p.add_argument('--sender-cpu', type=int, help='pin sender to an allowed logical CPU')
    p.add_argument('--receiver-cpu', type=int, help='pin receiver to an allowed logical CPU')
    p.add_argument('--router-cpus', type=router_cpus, metavar='FORWARD,REVERSE,...',
                   help='one shared forward/reverse CPU pair, or one pair per path in path order; requires root')
    p.add_argument('--fault-path', type=int, default=0)
    p.add_argument('--fault-direction', choices=['forward', 'reverse', 'both'], default='forward',
                   help='direction impaired on the fault path; forward carries the offered application data')
    p.add_argument('--fault-at', type=positive, default=30)
    p.add_argument('--restore-at', type=positive, default=60)
    p.add_argument('--loss-percent', type=positive, default=5,
                   help='random loss percentage for the loss scenario; default 5')
    p.add_argument('--seed', type=int,
                   help='netem seed in [1,4294967295]; each directed path gets a distinct derived seed')
    p.add_argument('--reaction-seconds', type=positive, default=1)
    p.add_argument('--calibration-wire-mbps', type=positive, default=2880)
    p.add_argument('--output-dir', required=True)
    p.add_argument('--in-namespace', action='store_true', help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.seed is not None and not 1 <= args.seed <= 0xffffffff:
        p.error('seed must be in [1,4294967295]')
    if args.loss_percent > 100:
        p.error('loss-percent must be in (0,100]')
    repair_options = [getattr(args, option.replace('-', '_'))
                      for option, _, maximum, _ in LIMIT_OPTIONS if maximum == 65535]
    if any(value is not None and not 1 <= value <= 65535 for value in repair_options):
        p.error('repair request limits must be in [1,65535]')
    if args.mode == 'raw-udp' and any(value is not None for value in repair_options):
        p.error('repair request limits require a qlinq delivery mode')
    limit_options = [getattr(args, option.replace('-', '_'))
                     for option, _, maximum, _ in LIMIT_OPTIONS if maximum == 4294967295]
    if any(value is not None and not 1 <= value <= 4294967295 for value in limit_options):
        p.error('endpoint limits require positive uint32 values')
    for option, values in (('path-rates-mbps', args.path_rates_mbps),
                           ('path-rtts-ms', args.path_rtts_ms)):
        if values is not None and len(values) != args.paths:
            p.error(f'{option} requires exactly one value per configured path')
    if args.scenario == 'calibration' and (args.path_rates_mbps or args.path_rtts_ms):
        p.error('calibration is unshaped; per-path shaping options require another scenario')
    if args.mode == 'raw-udp' and args.source_policy != 'discard':
        p.error('source-policy retry requires a qlinq delivery mode')
    if args.mode == 'raw-udp' and args.receive_delivery != 'queue':
        p.error('receive-delivery callback requires a qlinq delivery mode')
    if args.record_bytes is None:
        args.record_bytes = 1250 if args.mode == 'raw-udp' else 8000
    if args.mode == 'raw-udp' and args.record_bytes > 1400:
        p.error('raw-udp requires record-bytes <= 1400 to avoid fragmentation')
    if not (args.warmup+2 < args.seconds <= 3600 and .1 <= args.drain <= 60 and args.mbps <= 100000 and .1 <= args.deadline_ms <= 60000):
        p.error('require warmup+2 < seconds <= 3600, drain in [0.1,60], Mbps <= 100000, deadline-ms in [0.1,60000]')
    if not 0 <= args.fault_path < args.paths:
        p.error('fault-path must identify a configured path')
    if args.fault_direction != 'forward' and args.scenario in ('healthy', 'calibration'):
        p.error('fault-direction requires a fault scenario')
    if args.recovery_mbps is not None:
        if args.fault_direction == 'reverse':
            p.error('recovery-mbps requires impaired forward capacity; reverse-only reuse needs separate control-path evidence')
        other_capacity = sum(path_profile(args, i)[0] for i in range(args.paths) if i != args.fault_path)
        if (args.scenario in ('healthy', 'calibration') or args.mode == 'raw-udp' or
                args.recovery_mbps > 100000 or args.recovery_mbps <= args.mbps or
                (args.recovery_mbps * .9 <= other_capacity and
                 args.recovery_restored_path_min_mbps is None) or
                (args.recovery_restored_path_min_mbps is not None and
                 args.recovery_restored_path_min_mbps > args.recovery_mbps) or
                args.restore_at + 10 >= args.seconds):
            p.error('recovery requires a qlinq fault run, higher Mbps <=100000, either 90% above other-path capacity or an explicit restored-path minimum, and >10 seconds after restoration')
    elif args.recovery_restored_path_min_mbps is not None:
        p.error('recovery-restored-path-min-mbps requires recovery-mbps')
    reaction = fault_reaction_seconds(args)
    if args.scenario not in ('healthy', 'calibration') and not (args.warmup < args.fault_at < args.fault_at+reaction+1 < args.restore_at < args.seconds):
        p.error('require warmup < fault-at and a measured fault interval before restore-at < seconds')
    if args.router_cpus is not None and len(args.router_cpus) not in (2, 2 * args.paths):
        p.error('router-cpus requires one shared pair or exactly one pair per configured path')
    if args.router_cpus is not None and os.geteuid() != 0:
        p.error('router-cpus requires root for RPS; omit it to use unprivileged user namespaces')
    for cpu in (args.sender_cpu, args.receiver_cpu, *(args.router_cpus or ())):
        if cpu is not None and (cpu not in os.sched_getaffinity(0) or not shutil.which('taskset')):
            p.error('CPU pinning requires taskset and an allowed CPU index')
    os.chdir(ROOT)
    args.output_dir = str(Path(args.output_dir).resolve())
    if not args.in_namespace:
        for tool in ('unshare', 'nsenter', 'ip', 'tc', 'ethtool', 'sysctl'):
            if not shutil.which(tool):
                p.error(f'missing tool: {tool}')
        binary_name = 'transit_udp_calibration' if args.mode == 'raw-udp' else 'transit_benchmark'
        command('make', 'examples/'+binary_name, *([] if args.mode == 'raw-udp' else ['gencerts']))
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        identity = git_identity(ROOT) or {}
        dependency_git = {name: git_identity(ROOT / 'deps' / name)
                          for name in ('quicly', 'pathflow', 'nanorq', 'nanors', 'quicly/deps/picotls')}
        metadata = {'arguments': vars(args), 'commit': identity.get('commit'),
                    'tracked_diff_sha256': identity.get('tracked_diff_sha256'),
                    'requested_netem_seeds': [
                        {'path': i, **{d: netem_seed(args, i, d) for d in ('forward', 'reverse')}}
                        for i in range(args.paths)] if args.scenario != 'calibration' else [],
                    'kernel': command('uname', '-sr').strip(),
                    'allowed_cpus': sorted(os.sched_getaffinity(0)), 'load_average': os.getloadavg(),
                    'offloads': 'GSO/GRO/TSO, UDP segmentation and GRO forwarding disabled; per-veth verification in offloads.json',
                    'dependencies': {name: (value or {}).get('commit') for name, value in dependency_git.items()},
                    'dependency_git': dependency_git,
                    'git_provenance_note': 'Null means no Git checkout rooted at that directory. Unversioned copies require an experiment source manifest; parent repository revisions are not source identities.',
                    'binary_sha256': hashlib.sha256((ROOT / 'examples' / binary_name).read_bytes()).hexdigest(),
                    'harness_sha256': {name: hashlib.sha256((ROOT / 'examples' / name).read_bytes()).hexdigest()
                                       for name in (binary_name+'.c', 'multipath_transit_demo',
                                                    'transit_demo.py', 'transit_report.py', 'transit_fixture.py')},
                    'latency_clock': 'same-host CLOCK_MONOTONIC; not a cross-host latency benchmark'}
        (out / 'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
        env = dict(os.environ, QLINQ_TRANSIT_PARENT_NETNS=str(os.stat('/proc/self/ns/net').st_ino))
        # Only the opt-in RPS fixture retains root capability. Both paths enter
        # a new network namespace before touching interfaces or routing.
        isolation = '-mn' if args.router_cpus is not None else '-Urn'
        return subprocess.call(['unshare', isolation, sys.executable, str(ROOT / 'examples/multipath_transit_demo'), *sys.argv[1:], '--in-namespace'], env=env)
    if os.environ.get('QLINQ_TRANSIT_PARENT_NETNS') in (None, str(os.stat('/proc/self/ns/net').st_ino)):
        p.error('must be launched through the isolated namespace')
    return run(args)



