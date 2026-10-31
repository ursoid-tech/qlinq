#!/usr/bin/env python3
"""Enforce the standalone engine's native-I/O link boundary (ELF build)."""
from pathlib import Path
import re
import subprocess
import sys

binary = Path(sys.argv[1] if len(sys.argv) > 1 else 't/00util/test_transport_engine')
link_map = Path(str(binary) + '.map').read_text()
for name in ('transport_poll_host.o', 'transport_udp.o', 'ifmon.o', 'qlinq.o'):
    assert not re.search(r'^LOAD .*[/]' + re.escape(name) + r'$', link_map, re.M), name
symbols = subprocess.check_output(['nm', str(binary)], text=True)
for name in ('transport_create', 'transport_tick', 'transport_tick_ready',
             'transport_get_poll_fds', 'transport_rx_cadence_mask',
             'transport_enable_qlog'):
    assert not re.search(r'\b' + name + r'$', symbols, re.M), name
undefined = subprocess.check_output(['nm', '-u', str(binary)], text=True)
for name in ('socket', 'bind', 'connect', 'getsockname', 'getsockopt', 'setsockopt',
             'sendto', 'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg', 'recvmmsg',
             'poll', 'ppoll', 'pipe', 'pipe2', 'getifaddrs', 'if_indextoname'):
    assert not re.search(r'\b' + name + r'(?:@\S*)?$', undefined, re.M), name
assert not re.search(r'\b(?:ifmon_|__wrap_socket|__wrap_pipe)\w*$', symbols, re.M)
print('===TRANSPORT ENGINE LINK OK===')
