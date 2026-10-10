'''Signed-pointer content-hash binding verifier.'''
'''Read-only helper for off-chain pointer checks.'''

import datetime
import hashlib
import html
import re
import time
import urllib.request

NORMALIZATION_VERSION = 'norm-v1'
TOOL_NAME = 'technocore-signed-pointer-content-hash-binding-verifier'
TOOL_VERSION = '1.0.0'
MAX_BODY_BYTES = 2000000


def utc_now_iso():
    dt = datetime.datetime.now(datetime.timezone.utc)
    return dt.isoformat().replace('+00:00', 'Z')


def strip_html(raw):
    s = html.unescape(raw)
    s = re.sub(r'<script[^>]*>.*?</script>', ' ', s, flags=re.IGNORECASE | re.DOTALL)
    s = re.sub(r'<style[^>]*>.*?</style>', ' ', s, flags=re.IGNORECASE | re.DOTALL)
    s = re.sub(r'<[^>]+>', ' ', s)
    s = re.sub('[' + ' ' + chr(9) + ']+', ' ', s)
    return s


def normalize_text(raw):
    if raw is None:
        return ''
    if not isinstance(raw, str):
        raw = str(raw)
    s = html.unescape(raw)
    if '<' in s and '>' in s:
        s = strip_html(s)
    s = s.replace(chr(13) + chr(10), chr(10))
    s = s.replace(chr(13), chr(10))
    parts = s.split(chr(10))
    cleaned = []
    for line in parts:
        cleaned.append(line.rstrip(' ' + chr(9)))
    s = chr(10).join(cleaned)
    s = re.sub(chr(10) + '{3,}', chr(10) + chr(10), s)
    s = s.strip(' ' + chr(9) + chr(10))
    return s


def sha256_hex(normalized):
    data = normalized.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hash_content(raw):
    norm = normalize_text(raw)
    digest = sha256_hex(norm)
    return norm, digest


def is_hex64(value):
    if not isinstance(value, str):
        return False
    if len(value) != 64:
        return False
    low = value.lower()
    for ch in low:
        if ch not in '0123456789abcdef':
            return False
    return True


def parse_payload(payload):
    out = {'url': '', 'content_hash': '', 'did': '', 'signed_at': ''}
    if not isinstance(payload, dict):
        return out
    url = payload.get('url', '')
    if not url:
        url = payload.get('link', '')
    if not url:
        url = payload.get('article_url', '')
    digest = payload.get('content_hash', '')
    if not digest:
        digest = payload.get('contentHash', '')
    if not digest:
        digest = payload.get('body_hash', '')
    if not digest:
        digest = payload.get('article_hash', '')
    did = payload.get('did', '')
    if not did:
        did = payload.get('author_did', '')
    signed_at = payload.get('signed_at', '')
    if not signed_at:
        signed_at = payload.get('signedAt', '')
    if not isinstance(url, str):
        url = str(url)
    if not isinstance(digest, str):
        digest = str(digest)
    if not isinstance(did, str):
        did = str(did)
    if not isinstance(signed_at, str):
        signed_at = str(signed_at)
    digest = digest.strip().lower()
    if digest.startswith('0x'):
        digest = digest[2:]
    out['url'] = url.strip()
    out['content_hash'] = digest.strip()
    out['did'] = did.strip()
    out['signed_at'] = signed_at.strip()
    return out


def verify_one(payload, fetched_ok, fetched_text):
    parsed = parse_payload(payload)
    url = parsed['url']
    expected = parsed['content_hash']
    checked = utc_now_iso()
    base = {
        'url': url,
        'did': parsed['did'],
        'signed_at': parsed['signed_at'],
        'checked_at': checked,
        'normalization': NORMALIZATION_VERSION,
        'expected_hash': expected,
        'observed_hash': '',
        'observed_len': 0,
        'normalized_len': 0,
        'status': 'UNREACHABLE',
        'note': '',
    }
    if not url:
        base['note'] = 'missing url in payload'
        return base
    if not fetched_ok:
        base['note'] = 'fetch failed or body unavailable'
        return base
    if fetched_text is None:
        base['note'] = 'no body returned'
        return base
    norm, observed = hash_content(fetched_text)
    base['observed_hash'] = observed
    base['observed_len'] = len(fetched_text)
    base['normalized_len'] = len(norm)
    if not expected:
        base['status'] = 'MISSING-HASH'
        base['note'] = 'payload has no embedded hash'
        return base
    if not is_hex64(expected):
        base['status'] = 'MISSING-HASH'
        base['note'] = 'embedded hash is not 64 char hex'
        return base
    if expected == observed:
        base['status'] = 'MATCH'
        base['note'] = 'observed body matches embedded hash'
    else:
        base['status'] = 'MISMATCH'
        base['note'] = 'observed body differs from embedded hash'
    return base


def summarize_change(old_raw, new_raw):
    old_norm, old_hash = hash_content(old_raw or '')
    new_norm, new_hash = hash_content(new_raw or '')
    old_lines = 0
    new_lines = 0
    if old_norm:
        old_lines = len(old_norm.split(chr(10)))
    if new_norm:
        new_lines = len(new_norm.split(chr(10)))
    return {
        'changed': old_hash != new_hash,
        'old_hash': old_hash,
        'new_hash': new_hash,
        'old_len': len(old_norm),
        'new_len': len(new_norm),
        'len_delta': len(new_norm) - len(old_norm),
        'old_lines': old_lines,
        'new_lines': new_lines,
        'line_delta': new_lines - old_lines,
    }


def count_by_status(results):
    counts = {'MATCH': 0, 'MISMATCH': 0, 'MISSING-HASH': 0, 'UNREACHABLE': 0}
    for r in results:
        s = r.get('status', '')
        if s in counts:
            counts[s] += 1
    return counts


def build_json_report(results, reporter_did=''):
    if reporter_did is None:
        reporter_did = ''
    if not isinstance(reporter_did, str):
        reporter_did = str(reporter_did)
    return {
        'tool': TOOL_NAME,
        'tool_version': TOOL_VERSION,
        'normalization': NORMALIZATION_VERSION,
        'reporter_did': reporter_did,
        'checked_at': utc_now_iso(),
        'counts': count_by_status(results),
        'results': results,
    }


def build_markdown_report(report):
    lines = []
    lines.append('# Signed-Pointer Binding Report')
    lines.append('')
    lines.append('Tool: ' + str(report.get('tool', TOOL_NAME)))
    lines.append('Normalization: ' + str(report.get('normalization', '')))
    lines.append('Checked at: ' + str(report.get('checked_at', '')))
    lines.append('Reporter DID: ' + str(report.get('reporter_did', '')))
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    counts = report.get('counts', {})
    for key in ['MATCH', 'MISMATCH', 'MISSING-HASH', 'UNREACHABLE']:
        lines.append('- ' + key + ': ' + str(counts.get(key, 0)))
    lines.append('')
    lines.append('## Results')
    lines.append('')
    results = report.get('results', [])
    if not results:
        lines.append('No results.')
    for r in results:
        lines.append('### ' + str(r.get('url', '(no url)')))
        lines.append('- status: ' + str(r.get('status', '')))
        lines.append('- expected: ' + str(r.get('expected_hash', '')))
        lines.append('- observed: ' + str(r.get('observed_hash', '')))
        lines.append('- normalized_len: ' + str(r.get('normalized_len', 0)))
        lines.append('- did: ' + str(r.get('did', '')))
        lines.append('- checked_at: ' + str(r.get('checked_at', '')))
        note = str(r.get('note', ''))
        if note:
            lines.append('- note: ' + note)
        if 'previous_hash' in r:
            lines.append('- previous_hash: ' + str(r.get('previous_hash', '')))
            lines.append('- drift: ' + str(r.get('drift', False)))
        lines.append('')
    lines.append('Point-in-time observation.')
    lines.append('Binding holds only if hash was embedded at signing time.')
    return chr(10).join(lines)


def default_fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'technocore-hash-verifier/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY_BYTES + 1)
            if len(raw) > MAX_BODY_BYTES:
                raw = raw[:MAX_BODY_BYTES]
            try:
                text = raw.decode('utf-8')
            except Exception:
                text = raw.decode('utf-8', errors='replace')
            return True, text, ''
    except Exception as e:
        msg = str(e)
        if len(msg) > 300:
            msg = msg[:300]
        return False, '', msg


def batch_verify(payloads, fetcher=None, cache=None, max_retries=1, retry_delay=0.5):
    if cache is None:
        cache = {}
    if fetcher is None:
        fetcher = default_fetch
    results = []
    for payload in payloads:
        parsed = parse_payload(payload)
        url = parsed['url']
        ok = False
        text = ''
        err = ''
        tries = 0
        while tries <= max_retries:
            try:
                ok, text, err = fetcher(url)
            except Exception as e:
                ok = False
                text = ''
                msg = str(e)
                if len(msg) > 300:
                    msg = msg[:300]
                err = msg
            if ok:
                break
            tries += 1
            if tries <= max_retries:
                try:
                    time.sleep(retry_delay)
                except Exception:
                    break
        res = verify_one(payload, ok, text if ok else None)
        if not ok:
            res['fetch_error'] = err
        prev = cache.get(url)
        if isinstance(prev, dict) and ok:
            prev_hash = prev.get('observed_hash', '')
            cur_hash = res.get('observed_hash', '')
            if prev_hash and cur_hash and prev_hash != cur_hash:
                res['drift'] = True
                res['previous_hash'] = prev_hash
            else:
                res['drift'] = False
        else:
            res['drift'] = False
        if ok:
            cache[url] = {'observed_hash': res.get('observed_hash', ''), 'checked_at': res.get('checked_at', '')}
        results.append(res)
    return results
