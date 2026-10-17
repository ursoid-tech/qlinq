"""Recompute diagnostic gates from a saved transit trial without network access."""
import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from transit_report import analyze, events


def replay(directory, exits=None):
    directory = Path(directory)
    arguments = json.loads((directory / 'metadata.json').read_text())['arguments']
    if exits is None:
        exit_path = directory / 'endpoint-exits.json'
        if exit_path.exists():
            exits = json.loads(exit_path.read_text())
        else:
            # Older trials recorded process success only in their report. This
            # supplies the original process outcome, never the original gates.
            complete = json.loads((directory / 'report.json').read_text())['checks']['endpoints_completed']
            if type(complete) is not bool:
                raise ValueError('original endpoint completion must be boolean')
            exits = [0, 0] if complete else [1, 1]
    if not isinstance(exits, list) or len(exits) != 2 or any(type(code) is not int for code in exits):
        raise ValueError('require two integer endpoint exit codes')
    return analyze(events(directory / 'send.jsonl'), events(directory / 'receive.jsonl'),
                   json.loads((directory / 'queues.json').read_text()),
                   SimpleNamespace(**arguments), exits,
                   json.loads((directory / 'faults.json').read_text()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='saved trial directory')
    parser.add_argument('--exits', nargs=2, type=int, metavar=('SEND', 'RECEIVE'),
                        help='original process exit codes when not saved')
    args = parser.parse_args()
    try:
        report = replay(args.directory, args.exits)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
