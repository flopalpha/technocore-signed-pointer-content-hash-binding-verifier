'''Tests for signed-pointer binding verifier.'''

import json
import pathlib
import tempfile
import unittest

import verifier


class TestNormalize(unittest.TestCase):
    def test_strip_html(self):
        raw = '<p>Hello <b>world</b></p>'
        norm = verifier.normalize_text(raw)
        self.assertIn('Hello', norm)
        self.assertIn('world', norm)
        self.assertNotIn('<p>', norm)

    def test_line_ending_norm(self):
        a = 'line1' + chr(13) + chr(10) + 'line2' + chr(13) + 'line3'
        b = 'line1' + chr(10) + 'line2' + chr(10) + 'line3'
        self.assertEqual(verifier.normalize_text(a), verifier.normalize_text(b))

    def test_hash_stable(self):
        body = 'Hello Technocore'
        _, h1 = verifier.hash_content(body)
        _, h2 = verifier.hash_content(body)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_trailing_space_ignored(self):
        a = 'hello   '
        b = 'hello'
        _, ha = verifier.hash_content(a)
        _, hb = verifier.hash_content(b)
        self.assertEqual(ha, hb)


class TestVerify(unittest.TestCase):
    def test_match(self):
        body = 'Guide body text v1.'
        _, digest = verifier.hash_content(body)
        payload = {'url': 'https://example.com/a', 'content_hash': digest, 'did': 'did:example:1'}
        res = verifier.verify_one(payload, True, body)
        self.assertEqual(res['status'], 'MATCH')
        self.assertEqual(res['observed_hash'], digest)

    def test_mismatch(self):
        body = 'Guide body text v1.'
        _, digest = verifier.hash_content(body)
        payload = {'url': 'https://example.com/a', 'content_hash': digest}
        res = verifier.verify_one(payload, True, 'Guide body text v2 edited.')
        self.assertEqual(res['status'], 'MISMATCH')

    def test_missing_hash(self):
        payload = {'url': 'https://example.com/a', 'did': 'did:example:1'}
        res = verifier.verify_one(payload, True, 'some body')
        self.assertEqual(res['status'], 'MISSING-HASH')

    def test_bad_hash_shape(self):
        payload = {'url': 'https://example.com/a', 'content_hash': 'zzz'}
        res = verifier.verify_one(payload, True, 'some body')
        self.assertEqual(res['status'], 'MISSING-HASH')

    def test_unreachable(self):
        _, digest = verifier.hash_content('x')
        payload = {'url': 'https://example.com/a', 'content_hash': digest}
        res = verifier.verify_one(payload, False, None)
        self.assertEqual(res['status'], 'UNREACHABLE')

    def test_missing_url(self):
        payload = {'content_hash': 'a' * 64}
        res = verifier.verify_one(payload, False, None)
        self.assertEqual(res['status'], 'UNREACHABLE')

    def test_drift_summary(self):
        info = verifier.summarize_change('hello', 'hello world')
        self.assertTrue(info['changed'])
        self.assertGreater(info['new_len'], info['old_len'])

    def test_no_change(self):
        info = verifier.summarize_change('same', 'same')
        self.assertFalse(info['changed'])


class TestReports(unittest.TestCase):
    def test_json_and_markdown(self):
        body = 'Report body.'
        _, digest = verifier.hash_content(body)
        payloads = [{'url': 'https://example.com/a', 'content_hash': digest}]
        def fake_fetch(url):
            return True, body, ''
        cache = {}
        results = verifier.batch_verify(payloads, fetcher=fake_fetch, cache=cache, max_retries=0, retry_delay=0)
        report = verifier.build_json_report(results, reporter_did='did:example:auditor')
        self.assertEqual(report['counts']['MATCH'], 1)
        md = verifier.build_markdown_report(report)
        self.assertIn('MATCH', md)
        self.assertIn('https://example.com/a', md)
        with tempfile.TemporaryDirectory() as tmp:
            out_json = pathlib.Path(tmp) / 'report.json'
            out_md = pathlib.Path(tmp) / 'report.md'
            out_json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
            out_md.write_text(md, encoding='utf-8')
            back = json.loads(out_json.read_text(encoding='utf-8'))
            self.assertEqual(back['counts']['MATCH'], 1)
            self.assertIn('Signed-Pointer', out_md.read_text(encoding='utf-8'))

    def test_batch_drift_and_cache_file(self):
        store = {'https://example.com/a': 'first version'}
        def fake_fetch(url):
            if url in store:
                return True, store[url], ''
            return False, '', 'not found'
        _, d1 = verifier.hash_content('first version')
        payloads = [{'url': 'https://example.com/a', 'content_hash': d1}]
        cache = {}
        r1 = verifier.batch_verify(payloads, fetcher=fake_fetch, cache=cache, max_retries=0, retry_delay=0)
        self.assertEqual(r1[0]['status'], 'MATCH')
        self.assertFalse(r1[0]['drift'])
        store['https://example.com/a'] = 'second version edited'
        r2 = verifier.batch_verify(payloads, fetcher=fake_fetch, cache=cache, max_retries=0, retry_delay=0)
        self.assertEqual(r2[0]['status'], 'MISMATCH')
        self.assertTrue(r2[0]['drift'])
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = pathlib.Path(tmp) / 'cache.json'
            cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding='utf-8')
            loaded = json.loads(cache_path.read_text(encoding='utf-8'))
            self.assertIn('https://example.com/a', loaded)

    def test_batch_unreachable(self):
        def bad_fetch(url):
            return False, '', 'blocked'
        _, d = verifier.hash_content('x')
        payloads = [{'url': 'https://example.com/b', 'content_hash': d}]
        results = verifier.batch_verify(payloads, fetcher=bad_fetch, cache={}, max_retries=0, retry_delay=0)
        self.assertEqual(results[0]['status'], 'UNREACHABLE')

    def test_parse_aliases(self):
        p = {'link': 'https://example.com/x', 'body_hash': 'A' * 64}
        parsed = verifier.parse_payload(p)
        self.assertEqual(parsed['url'], 'https://example.com/x')
        self.assertEqual(parsed['content_hash'], 'a' * 64)


if __name__ == '__main__':
    unittest.main()
