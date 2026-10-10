'''Batch CLI for signed-pointer binding verifier.'''

import argparse
import json
import pathlib

import verifier


def read_json_list(path):
    text = pathlib.Path(path).read_text(encoding='utf-8')
    data = json.loads(text)
    if isinstance(data, dict) and 'payloads' in data:
        data = data['payloads']
    if not isinstance(data, list):
        raise ValueError('payloads file must hold a JSON list')
    return data


def read_cache(path):
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    text = p.read_text(encoding='utf-8')
    data = json.loads(text)
    if isinstance(data, dict):
        return data
    return {}


def write_text(path, content):
    p = pathlib.Path(path)
    parent = str(p.parent)
    if parent not in ('.', ''):
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')


def build_parser():
    parser = argparse.ArgumentParser(description='Verify signed pointers.')
    parser.add_argument('--payloads', required=True, help='Path to JSON list.')
    parser.add_argument('--out-json', default='report.json', help='Path for JSON report.')
    parser.add_argument('--out-md', default='report.md', help='Path for Markdown report.')
    parser.add_argument('--cache', default='cache.json', help='Path for cache.')
    parser.add_argument('--reporter-did', default='', help='DID of reporter.')
    parser.add_argument('--retries', type=int, default=1, help='Retries per URL.')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between tries.')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    payloads = read_json_list(args.payloads)
    cache = {}
    cache_path = pathlib.Path(args.cache)
    if cache_path.exists():
        try:
            cache = read_cache(args.cache)
        except Exception:
            cache = {}
    results = verifier.batch_verify(payloads, cache=cache, max_retries=args.retries, retry_delay=args.delay)
    report = verifier.build_json_report(results, reporter_did=args.reporter_did)
    write_text(args.out_json, json.dumps(report, indent=2, sort_keys=True))
    write_text(args.out_md, verifier.build_markdown_report(report))
    try:
        write_text(args.cache, json.dumps(cache, indent=2, sort_keys=True))
    except Exception:
        pass
    counts = report.get('counts', {})
    print('MATCH: ' + str(counts.get('MATCH', 0)))
    print('MISMATCH: ' + str(counts.get('MISMATCH', 0)))
    print('MISSING-HASH: ' + str(counts.get('MISSING-HASH', 0)))
    print('UNREACHABLE: ' + str(counts.get('UNREACHABLE', 0)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
