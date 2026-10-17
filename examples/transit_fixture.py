"""Isolated namespace, shaping, offload and CPU-placement operations."""
import argparse
import json
import math
import os
import subprocess
import time

from transit_report import fault_directions, path_profile


DISABLED_OFFLOADS = {
    'gro': 'generic-receive-offload',
    'gso': 'generic-segmentation-offload',
    'tso': 'tcp-segmentation-offload',
    'tx-udp-segmentation': 'tx-udp-segmentation',
    'tx-gso-list': 'tx-gso-list',
    'rx-gro-list': 'rx-gro-list',
    'rx-udp-gro-forwarding': 'rx-udp-gro-forwarding',
}


def command(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True).stdout



def netem_seed(args, index, direction):
    seed = getattr(args, 'seed', None)
    if seed is None:
        return None
    # Distinct, stable nonzero seeds for each directed path, including wraparound.
    return (seed - 1 + 2 * index + (direction == 'reverse')) % 0xffffffff + 1



def apply_path_fault(topo, args, routers, forward, reverse, fault):
    index = args.fault_path
    for direction in fault_directions(args):
        dev = forward[index] if direction == 'forward' else reverse[index]
        options = {'replace': True}
        seed = netem_seed(args, index, direction)
        if seed is not None:
            options['seed'] = seed
        topo.shape(routers[index], dev, *path_profile(args, index, fault=fault), **options)



def parse_snmp(contents):
    """Namespace counters survive endpoint exit, including UDP socket drops."""
    lines = contents.splitlines()
    for i in range(len(lines) - 1):
        keys, values = lines[i].split(), lines[i + 1].split()
        if len(keys) > 1 and len(keys) == len(values) and keys[0] == values[0] == 'Udp:' and keys[1] == 'InDatagrams':
            return dict(zip(keys[1:], map(int, values[1:])))
    raise RuntimeError('missing UDP network counters')



def parse_offloads(contents):
    features = {}
    for line in contents.splitlines():
        name, separator, value = line.partition(':')
        state = value.strip().split()
        if separator and state and state[0] in ('on', 'off'):
            features[name.strip()] = state[0]
    return features



def router_cpus(text):
    try:
        cpus = tuple(map(int, text.split(',')))
    except ValueError:
        cpus = ()
    if len(cpus) not in (2, 4, 6, 8) or any(cpu < 0 for cpu in cpus):
        raise argparse.ArgumentTypeError('expected nonnegative forward,reverse CPU indices: one pair or one pair per path')
    return cpus



def router_cpu_pair(cpus, path):
    first = 0 if len(cpus) == 2 else 2 * path
    return cpus[first:first + 2]



def cpu_mask(cpu):
    chunks = ['00000000'] * (cpu // 32) + [f'{1 << (cpu % 32):08x}']
    return ','.join(reversed(chunks))



class Topology:
    def __init__(self):
        self.keepers = []
        self.offloads = []
        self.rps = []

    def namespace(self):
        p = subprocess.Popen(['unshare', '-n', 'sleep', '1000000'])
        self.keepers.append(p)
        parent = os.readlink('/proc/self/ns/net')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if p.poll() is not None:
                raise RuntimeError('namespace keeper failed')
            if os.readlink(f'/proc/{p.pid}/ns/net') != parent:
                return p.pid
            time.sleep(.01)
        raise RuntimeError('namespace creation timeout')

    @staticmethod
    def prefix(pid):
        return ['nsenter', '-t', str(pid), '-n']

    def cmd(self, pid, *args):
        return command(*self.prefix(pid), *args)

    def disable_offloads(self, pid, dev):
        # Generic GSO alone does not disable UDP_SEGMENT on veth. Segment at
        # the sender, before router netem queues count packets or apply loss.
        settings = [value for name in DISABLED_OFFLOADS for value in (name, 'off')]
        self.cmd(pid, 'ethtool', '-K', dev, *settings)
        features = parse_offloads(self.cmd(pid, 'ethtool', '-k', dev))
        self.offloads.append({'namespace_pid': pid, 'interface': dev,
                              'features': features})
        invalid = [name for name in DISABLED_OFFLOADS.values()
                   if features.get(name) != 'off']
        if invalid:
            raise RuntimeError(f'{dev}: offload verification failed: {", ".join(invalid)}')

    def steer_receive(self, pid, dev, cpu, mountpoint):
        # RPS needs initial-user-namespace CAP_NET_ADMIN on this kernel. Mount
        # sysfs for this router in a temporary private mount namespace; never
        # address host interfaces through the host's /sys mount.
        observed = self.cmd(pid, 'unshare', '-m', 'sh', '-eu', '-c',
            'mount --make-rprivate /; mount -t sysfs sysfs "$1"; '
            'printf %s "$3" > "$1/class/net/$2/queues/rx-0/rps_cpus"; '
            'cat "$1/class/net/$2/queues/rx-0/rps_cpus"',
            'rps', mountpoint, dev, cpu_mask(cpu)).strip()
        self.rps.append({'namespace_pid': pid, 'interface': dev,
                         'cpu': cpu, 'observed_mask': observed})
        try:
            matches = int(observed.replace(',', ''), 16) == 1 << cpu
        except ValueError:
            matches = False
        if not matches:
            raise RuntimeError(f'{dev}: RPS readback mismatch')

    def pair(self, left, right, name, left_ip, right_ip):
        a, b = name+'a', name+'b'
        command('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
        for pid, dev, ip in ((left, a, left_ip), (right, b, right_ip)):
            command('ip', 'link', 'set', dev, 'netns', pid)
            self.cmd(pid, 'ip', 'address', 'add', ip+'/30', 'dev', dev)
            self.cmd(pid, 'ip', 'link', 'set', dev, 'up')
            self.disable_offloads(pid, dev)
        return a, b

    def shape(self, pid, dev, rate, delay, loss=0, replace=False, seed=None):
        verb = 'change' if replace else 'add'
        if not replace:
            self.cmd(pid, 'tc', 'qdisc', 'add', 'dev', dev, 'root', 'handle', '1:', 'htb', 'default', '10')
        self.cmd(pid, 'tc', 'class', verb, 'dev', dev, 'parent', '1:', 'classid', '1:10', 'htb',
                 'rate', f'{rate}mbit', 'ceil', f'{rate}mbit', 'burst', '64kb', 'cburst', '64kb')
        # Preserve propagation delay plus up to 100 ms extra at the nominal cap.
        limit = max(128, math.ceil(rate * 1e6 * (delay+100) / (1000*8*1280)))
        self.cmd(pid, 'tc', 'qdisc', verb, 'dev', dev, 'parent', '1:10', 'handle', '10:', 'netem',
                 'delay', f'{delay}ms', 'limit', limit, 'loss', f'{loss}%',
                 *([] if seed is None else ['seed', seed]))

    def counters(self, pid, dev, shaped):
        if shaped:
            rows = json.loads(self.cmd(pid, 'tc', '-j', '-s', 'class', 'show', 'dev', dev))
            return next(r.get('stats', r) for r in rows if r.get('handle') == '1:10')
        row = json.loads(self.cmd(pid, 'ip', '-j', '-s', 'link', 'show', 'dev', dev))[0]
        return row.get('stats64', row.get('stats'))['tx']

    def close(self):
        for p in self.keepers:
            p.terminate()
        for p in self.keepers:
            p.wait(timeout=3)



