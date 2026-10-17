"""Pure transit report calculations shared by live trials and report replay."""
import json
import math


def events(path):
    result = []
    if path.exists():
        for line in path.read_text().splitlines():
            if line.startswith('{'):
                try:
                    result.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # The writer may be halfway through a line.
    return result



def delivery_cohorts(tx, rx):
    """Match delivery to first submission, including records arriving in drain."""
    indexed = []
    for summary in (tx, rx):
        if not isinstance(summary.get('source_cohorts'), list):
            return [], False
        rows = {}
        for row in summary['source_cohorts']:
            if not isinstance(row, dict):
                return [], False
            second = row.get('second')
            if not isinstance(second, int) or not 0 <= second <= 3600 or second in rows:
                return [], False
            if any(not isinstance(row.get(key), int) or row[key] < 0
                   for key in ('offered', 'admitted', 'received', 'late')):
                return [], False
            rows[second] = row
        indexed.append(rows)
    source, sink = indexed
    complete = all(sum(row[key] for row in rows.values()) == summary.get(total)
                   for rows, summary, key, total in (
                       (source, tx, 'offered', 'offered'), (source, tx, 'admitted', 'admitted'),
                       (sink, rx, 'received', 'received'), (sink, rx, 'late', 'received_late')))
    cohorts = []
    for second in sorted(source.keys() | sink.keys()):
        offered = source.get(second, {}).get('offered', 0)
        admitted = source.get(second, {}).get('admitted', 0)
        received = sink.get(second, {}).get('received', 0)
        late = sink.get(second, {}).get('late', 0)
        complete &= 0 <= late <= received <= admitted <= offered
        cohorts.append({'second': second, 'offered': offered, 'admitted': admitted,
                        'received': received, 'late': late,
                        'missing_admitted': admitted - received,
                        'received_in_time': received - late})
    return cohorts, complete



def path_profile(args, index, fault=False):
    """Emulator configuration only; never passed to qlinq's scheduler."""
    rates = getattr(args, 'path_rates_mbps', None)
    rtts = getattr(args, 'path_rtts_ms', None)
    rate = rates[index] if rates else args.rate_mbps
    rtt = rtts[index] if rtts else args.rtt_ms
    delay, loss = rtt / 2, 0
    if fault:
        if args.scenario == 'capacity':
            rate /= 10
        elif args.scenario == 'delay':
            delay += 100
        elif args.scenario == 'loss':
            loss = getattr(args, 'loss_percent', 5)
        elif args.scenario == 'outage':
            loss = 100
    return rate, delay, loss



def fault_directions(args):
    direction = getattr(args, 'fault_direction', 'forward')
    return ('forward', 'reverse') if direction == 'both' else (direction,)



def wire_fraction(intervals, key, path, paths):
    if not intervals or any(len(r[key]) != paths or
                            any(not math.isfinite(v) or v < 0 for v in r[key])
                            for r in intervals):
        return None
    total = sum(sum(r[key]) * (r['time'] - r['start']) for r in intervals)
    return (sum(r[key][path] * (r['time'] - r['start']) for r in intervals) / total
            if total > 0 else None)



def fault_reaction_seconds(args):
    _, one_way_ms, _ = path_profile(args, args.fault_path)
    return max(args.reaction_seconds, 10 * (2 * one_way_ms) / 1000)



def offered_megabits(args, start, end):
    recovery = getattr(args, 'recovery_mbps', None)
    if recovery is None:
        return (end - start) * args.mbps
    change = args.restore_at + 1
    before = max(0, min(end, change) - start)
    after = max(0, end - max(start, change))
    return before * args.mbps + after * recovery



def application_window(receiver, start, end):
    """Measure only counter intervals wholly inside a phase; exclude drain/catch-up."""
    rows = [e for e in receiver if e.get('event') == 'sample' and
            start <= e['time'] < end]
    if len(rows) < 2:
        return None
    for left, right in zip(rows, rows[1:]):
        if (not all(isinstance(row.get('received_bytes'), int) and
                    row['received_bytes'] >= 0 for row in (left, right)) or
                right['time'] <= left['time'] or
                right['received_bytes'] < left['received_bytes']):
            return None
    elapsed = rows[-1]['time'] - rows[0]['time']
    return {'start': rows[0]['time'], 'end': rows[-1]['time'],
            'samples': len(rows), 'measured_seconds': elapsed,
            'mbps': (rows[-1]['received_bytes'] - rows[0]['received_bytes']) * 8 / elapsed / 1e6}



def latency_window(receiver, start, end):
    """Combine validated interval histograms, excluding boundary-crossing bins."""
    rows = [e for e in receiver if e.get('event') == 'sample' and
            start <= e['time'] < end]
    if len(rows) < 2:
        return None
    histogram = [0] * 10001
    for left, right in zip(rows, rows[1:]):
        interval_start = right.get('interval_start')
        bins = right.get('latency_histogram_ms')
        if (not isinstance(interval_start, (int, float)) or
                not math.isclose(interval_start, left['time'], rel_tol=0, abs_tol=1e-6) or
                right['time'] <= left['time'] or not isinstance(bins, list) or
                any(type(row.get('received')) is not int or row['received'] < 0
                    for row in (left, right))):
            return None
        previous_bin, total = -1, 0
        for pair in bins:
            if (not isinstance(pair, list) or len(pair) != 2 or
                    any(type(value) is not int for value in pair) or
                    not previous_bin < pair[0] <= 10000 or pair[1] <= 0):
                return None
            previous_bin = pair[0]
            histogram[pair[0]] += pair[1]
            total += pair[1]
        if total != right['received'] - left['received']:
            return None
    records = sum(histogram)
    rank, count, percentile_bin = records - records // 100, 0, None
    if records:
        for index, size in enumerate(histogram):
            count += size
            if count >= rank:
                percentile_bin = index
                break
    return {'start': rows[0]['time'], 'end': rows[-1]['time'],
            'intervals': len(rows) - 1, 'records': records,
            'p99_ms': percentile_bin + 1 if percentile_bin is not None and percentile_bin < 10000 else None,
            'p99_censored': percentile_bin == 10000,
            'overflow_records': histogram[-1]}



def fault_checks(receiver, phase_rates, args, faults, checks):
    fault_application_rates = None
    fault_application_latency = None
    degraded_sent_wire_fraction = None
    fault_wire_shares = {}
    if args.scenario not in ('healthy', 'calibration'):
        applied = next((f['time'] for f in faults if f['event'] == 'fault'), None)
        restored = next((f['time'] for f in faults if f['event'] == 'restore'), None)
        checks['fault_applied_and_restored'] = applied is not None and restored is not None
        before_end = next((f.get('started_at', f['time']) for f in faults if f['event'] == 'fault'), None)
        degraded_end = next((f.get('started_at', f['time']) for f in faults if f['event'] == 'restore'), None)
        before_app = application_window(receiver, args.warmup, before_end) if applied is not None else None
        degraded_app = application_window(receiver, applied + fault_reaction_seconds(args), degraded_end) if applied is not None and restored is not None else None
        fault_application_rates = {'before': before_app, 'degraded': degraded_app}
        checks['fault_application_measurements_complete'] = bool(before_app and degraded_app)
        checks['pre_fault_goodput_90pct_offer'] = bool(before_app and before_app['mbps'] >= args.mbps * .9)
        checks['degraded_goodput_90pct_control'] = bool(before_app and degraded_app and before_app['mbps'] > 0 and degraded_app['mbps'] >= before_app['mbps'] * .9)
        before_latency = latency_window(receiver, args.warmup, before_end) if applied is not None else None
        degraded_latency = latency_window(receiver, applied + fault_reaction_seconds(args), degraded_end) if applied is not None and restored is not None else None
        fault_application_latency = {'before': before_latency, 'degraded': degraded_latency}
        checks['fault_latency_measurements_complete'] = bool(before_latency and degraded_latency and before_latency['records'] and degraded_latency['records'])
        checks['degraded_p99_within_control_plus_100ms'] = bool(
            checks['fault_latency_measurements_complete'] and
            before_latency['p99_ms'] is not None and degraded_latency['p99_ms'] is not None and
            degraded_latency['p99_ms'] <= before_latency['p99_ms'] + 100)

        before = [r for r in phase_rates if before_end is not None and r['time'] <= before_end]
        after = [r for r in phase_rates if applied is not None and degraded_end is not None and
                 applied + fault_reaction_seconds(args) <= r['start'] < r['time'] <= degraded_end]
        for direction in fault_directions(args):
            key = 'sent_mbps' if direction == 'forward' else 'reverse_sent_mbps'
            pre = wire_fraction(before, key, args.fault_path, args.paths)
            post = wire_fraction(after, key, args.fault_path, args.paths)
            fault_wire_shares[direction] = {'before': pre, 'degraded': post}
            prefix = '' if direction == 'forward' else 'reverse_'
            checks[prefix + 'fault_path_exercised'] = pre is not None and pre >= .1
            checks['degraded_' + prefix + 'sent_wire_share_below_10pct'] = post is not None and post <= .1
            if direction == 'forward':
                degraded_sent_wire_fraction = post
    return (fault_application_rates, fault_application_latency,
            degraded_sent_wire_fraction, fault_wire_shares)


def recovery_checks(sender, receiver, phase_rates, args, faults, checks):
    recovery_result = None
    recovery = getattr(args, 'recovery_mbps', None)
    if recovery is not None:
        restored = next((f['time'] for f in faults if f['event'] == 'restore'), None)
        changes = [e for e in sender if e.get('event') == 'rate_change']
        change = changes[0] if len(changes) == 1 else {}
        at = change.get('time')
        valid_change = (restored is not None and isinstance(at, (int, float)) and
                        restored <= at < restored + 5 and
                        change.get('mbps') == recovery and
                        change.get('scheduled_time') == args.restore_at + 1)
        other_capacity = sum(path_profile(args, i)[0] for i in range(args.paths) if i != args.fault_path)
        restored_path_minimum = getattr(args, 'recovery_restored_path_min_mbps', None)
        requires_path = recovery * .9 > other_capacity or restored_path_minimum is not None
        early = application_window(receiver, at, restored + 5) if valid_change else None
        sustained = application_window(receiver, restored + 5, args.seconds) if valid_change else None
        wire_intervals = [r for r in phase_rates if early and
                          early['start'] <= r['start'] < r['time'] <= early['end']]
        wire_complete = bool(wire_intervals) and all(
            len(r['path_mbps']) == args.paths and
            all(math.isfinite(v) and v >= 0 for v in r['path_mbps'])
            for r in wire_intervals)
        restored_wire = None
        if wire_complete:
            duration = sum(r['time'] - r['start'] for r in wire_intervals)
            restored_wire = sum(r['path_mbps'][args.fault_path] * (r['time'] - r['start'])
                                for r in wire_intervals) / duration
        checks['recovery_offer_requires_restored_path'] = requires_path
        checks['recovery_rate_change_recorded'] = bool(valid_change)
        checks['recovery_goodput_within_5s'] = bool(requires_path and early and early['mbps'] >= recovery * .9)
        checks['recovery_goodput_sustained'] = bool(requires_path and sustained and sustained['mbps'] >= recovery * .9)
        restored_wire_requirement = (restored_path_minimum if restored_path_minimum is not None
                                    else recovery * .9 - other_capacity)
        checks['restored_wire_use_within_5s'] = bool(requires_path and restored_wire is not None and
                                                   restored_wire >= restored_wire_requirement)
        recovery_result = {'scheduled_change': args.restore_at + 1, 'change': change,
                           'target_mbps': recovery, 'other_paths_capacity_mbps': other_capacity,
                           'minimum_restored_path_mbps': restored_wire_requirement,
                           'early_application': early, 'sustained_application': sustained,
                           'early_restored_wire_mbps': restored_wire}
    return recovery_result


def analyze(sender, receiver, samples, args, exits, faults=()):
    tx = next((e for e in reversed(sender) if e.get('event') == 'summary'), {})
    rx = next((e for e in reversed(receiver) if e.get('event') == 'summary'), {})
    expected = offered_megabits(args, 0, args.seconds) * 1e6 / (8 * args.record_bytes)
    active = [e for e in receiver if e.get('event') == 'sample' and args.warmup < e['time'] <= args.seconds]
    # Difference cumulative delivery counters over a common steady window;
    # post-run draining is excluded from throughput, included in final delivery.
    steady = [s for s in samples if args.warmup <= s['time'] <= args.seconds]
    measured = len(active) >= 2 and len(steady) >= 2 and bool(tx) and bool(rx)
    goodput = wire = 0
    steady_target = args.mbps
    if measured:
        elapsed = active[-1]['time'] - active[0]['time']
        goodput = (active[-1]['received_bytes'] - active[0]['received_bytes']) * 8 / elapsed / 1e6
        steady_target = offered_megabits(args, active[0]['time'], active[-1]['time']) / elapsed
        elapsed = steady[-1]['time'] - steady[0]['time']
        wire = sum(b['bytes'] - a['bytes'] for a, b in zip(steady[0]['forward'], steady[-1]['forward'])) * 8 / elapsed / 1e6
    offered, admitted = tx.get('offered', 0), tx.get('admitted', 0)
    mode = getattr(args, 'mode', 'fixed-fec')
    receive_delivery = getattr(args, 'receive_delivery', 'queue')
    fault = args.scenario not in ('healthy', 'calibration')
    checks = {
        'endpoints_completed': exits == [0, 0],
        'measurements_complete': measured,
        'generator_kept_up': expected > 0 and offered >= expected * .99,
        'integrity_and_deduplication': bool(rx) and rx.get('corrupt', 1) == 0 and rx.get('duplicates', 1) == 0 and rx.get('outside_reorder_window', 1) == 0,
        'steady_goodput_90pct_offer': measured and goodput >= steady_target * .9,
        'receive_delivery_mode': tx.get('receive_delivery', 'queue') == 'queue' and
                                 rx.get('receive_delivery', receive_delivery) == receive_delivery,
    }
    if receive_delivery == 'callback':
        checks['callback_avoids_public_record_copies'] = bool(rx) and \
            rx.get('record_events_queued') == 0 and \
            rx.get('record_payload_bytes_copied') == 0 and \
            rx.get('record_callbacks_accepted') == rx.get('received') and \
            rx.get('record_callbacks_rejected') == 0
    if mode in ('reliable', 'rateless'):
        delivery_requirement = 'all_admitted_within_bounded_drain'
        checks['all_admitted_delivered'] = admitted > 0 and rx.get('received', 0) == admitted
    elif mode == 'fixed-fec' and fault:
        # Fixed FEC intentionally does not repair loss beyond its parity budget.
        # Keep the deficit visible without imposing reliable-delivery semantics.
        delivery_requirement = 'best_effort_fault_loss_reported'
    else:
        delivery_requirement = '99_9pct_delivery'
        checks['admitted_delivery_99_9pct'] = admitted > 0 and rx.get('received', 0) >= admitted * .999
        checks['offered_delivery_99_9pct'] = offered > 0 and rx.get('received', 0) >= offered * .999
    deadline = getattr(args, 'deadline_ms', None) if mode != 'raw-udp' else None
    cohorts, cohort_complete = delivery_cohorts(tx, rx)
    received_in_time = sum(row['received_in_time'] for row in cohorts)
    if deadline is not None:
        declared = all(isinstance(e.get('deadline_ms'), (int, float)) and
                       math.isclose(e['deadline_ms'], deadline, rel_tol=0, abs_tol=.0005)
                       for e in (tx, rx))
        checks['source_cohort_accounting'] = cohort_complete and declared
        if args.scenario == 'healthy' and mode == 'fixed-fec':
            checks['deadline_delivery_99_9pct'] = checks['source_cohort_accounting'] and offered > 0 and received_in_time >= offered * .999
    if args.scenario == 'calibration':
        checks['fixture_wire_headroom'] = measured and wire >= args.calibration_wire_mbps
    phase_rates = []
    for left, right in zip(steady, steady[1:]):
        dt = right['time'] - left['time']
        phase_rates.append({'start': left['time'], 'time': right['time'], 'path_mbps': [(b['bytes']-a['bytes'])*8/dt/1e6 for a, b in zip(left['forward'], right['forward'])],
                            'sent_mbps': [(b['bytes']-a['bytes'])*8/dt/1e6 for a, b in zip(left.get('sent', []), right.get('sent', []))],
                            'reverse_sent_mbps': [(b['bytes']-a['bytes'])*8/dt/1e6 for a, b in zip(left.get('reverse_sent', []), right.get('reverse_sent', []))]})
    (fault_application_rates, fault_application_latency,
     degraded_sent_wire_fraction, fault_wire_shares) = fault_checks(
         receiver, phase_rates, args, faults, checks)
    recovery_result = recovery_checks(sender, receiver, phase_rates, args, faults, checks)
    return {'scenario': args.scenario, 'fault_direction': getattr(args, 'fault_direction', 'forward'),
            'fault_wire_shares': fault_wire_shares, 'qualified': False,
            'note': 'Diagnostic fixture only; full matrix, latency controls, repeats and physical-host qualification remain required.',
            'checks': checks, 'passed': all(checks.values()),
            'mode': mode, 'receive_delivery': receive_delivery,
            'delivery_requirement': delivery_requirement,
            'missing_admitted_records': admitted - rx.get('received', 0),
            'delivered_fraction_of_admitted': rx.get('received', 0) / admitted if admitted else 0,
            'source_policy': getattr(args, 'source_policy', 'discard'),
            'fault_application_rates': fault_application_rates,
            'fault_application_latency': fault_application_latency,
            'recovery': recovery_result,
            'degraded_sent_wire_fraction': degraded_sent_wire_fraction,
            'path_profiles': [{'path': i, 'rate_mbps': path_profile(args, i)[0],
                               'rtt_ms': path_profile(args, i)[1] * 2}
                              for i in range(getattr(args, 'paths', len(samples[0]['forward']) if samples else 0))],
            'expected_records': expected,
            'target_application_mbps': args.mbps,
            'steady_target_application_mbps': steady_target,
            # These averages cover the entire sending interval. Steady goodput
            # excludes warmup, so do not silently divide it by these averages.
            'actual_offered_average_mbps': offered * args.record_bytes * 8 / args.seconds / 1e6,
            'admitted_average_mbps': admitted * args.record_bytes * 8 / args.seconds / 1e6,
            'delivered_fraction_of_offered': rx.get('received', 0) / offered if offered else 0,
            'steady_goodput_fraction_of_target': goodput / steady_target,
            'steady_goodput_mbps': goodput,
            'deadline_ms': deadline,
            'deadline_delivered_fraction_of_offered': received_in_time / offered if checks.get('source_cohort_accounting') and offered else None,
            'delivery_by_source_second': cohorts,
            'steady_forward_wire_mbps': wire, 'sender': tx, 'receiver': rx,
            'path_rates': phase_rates}



