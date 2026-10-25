from gevent import monkey; monkey.patch_all()

import base64
import gzip
import hashlib
import json
import os
import time

from urllib.parse import parse_qsl, urlsplit

import pytest
import requests
import webtest

from fakeredis import FakeStrictRedis
from warcio import ArchiveIterator
from warcio.timeutils import timestamp_to_iso_date

from pywb.recorder.filters import WriteRevisitDupePolicy
from pywb.recorder.multifilewarcwriter import PerRecordWARCWriter
from pywb.recorder.recorderapp import RecorderApp
from pywb.recorder.redaction import JsonRedactPolicy
from pywb.recorder.redisindexer import WritableRedisIndexer
from pywb.utils.geventserver import GeventServer
from pywb.warcserver.index.cdxobject import CDXObject
from pywb.warcserver.test.testutils import BaseTestClass, FakeRedisTests, TempDirTests, to_path

import gevent


# ============================================================================
# Controlled upstream: emits raw WARC-framed HTTP responses with full control
# over status, headers, entity encoding and delivery timing.
# ============================================================================
USER = {
    "name": "Ann",
    "secret": "TOPSECRET",
    "items": ["keep0", "keep1"],
    "nested": {"token": "TKN", "ok": True},
}
USER_JSON = json.dumps(USER, indent=2).encode('utf-8')
USER_JSON_GZ = gzip.compress(USER_JSON, mtime=0)

# emitted while streaming, inspected by the streaming test
STREAM_EVENTS = []


def _spec(path):
    if path == '/api/user':
        return {'headers': [('Content-Type', 'application/json; charset=utf-8')],
                'body': USER_JSON}

    if path == '/api/user-gz':
        return {'headers': [('Content-Type', 'application/json'),
                            ('Content-Encoding', 'gzip')],
                'body': USER_JSON_GZ}

    if path == '/api/user-md5':
        md5 = base64.b64encode(hashlib.md5(USER_JSON).digest()).decode('ascii')
        return {'headers': [('Content-Type', 'application/json'),
                            ('Content-MD5', md5)],
                'body': USER_JSON}

    if path == '/api/user-nocharset':
        return {'headers': [('Content-Type', 'application/json')],
                'body': USER_JSON}

    if path == '/api/empty':
        return {'headers': [('Content-Type', 'application/json')],
                'body': b''}

    if path == '/api/html':
        return {'headers': [('Content-Type', 'text/html; charset=utf-8')],
                'body': b'<html>TOPSECRET</html>'}

    if path == '/api/badgzip':
        return {'headers': [('Content-Type', 'application/json'),
                            ('Content-Encoding', 'gzip')],
                'body': b'NOT-GZIP-TOPSECRET'}

    if path == '/api/truncgz':
        return {'headers': [('Content-Type', 'application/json'),
                            ('Content-Encoding', 'gzip')],
                'body': USER_JSON_GZ[:20]}

    if path == '/api/badjson':
        return {'headers': [('Content-Type', 'application/json')],
                'body': b'{ "secret": "TOPSECRET", broken'}

    if path == '/api/badenc':
        return {'headers': [('Content-Type', 'application/json'),
                            ('Content-Encoding', 'br')],
                'body': b'br-br-TOPSECRET'}

    if path == '/api/badcharset':
        return {'headers': [('Content-Type', 'application/json; charset=utf-16')],
                'body': USER_JSON.decode('utf-8').encode('utf-16')}

    if path == '/api/dup':
        return {'headers': [('Content-Type', 'application/json')],
                'body': USER_JSON}

    if path == '/api/big':
        big = json.dumps({"secret": "TOPSECRET", "pad": "x" * 600000})
        return {'headers': [('Content-Type', 'application/json')],
                'body': big.encode('utf-8'),
                'stream_delay': 0.4}

    if path == '/other/user':
        return {'headers': [('Content-Type', 'application/json')],
                'body': USER_JSON}

    raise KeyError(path)


def controlled_upstream(environ, start_response):
    params = dict(parse_qsl(environ.get('QUERY_STRING', '')))
    url = params.get('url', '')
    path = urlsplit(url).path

    spec = _spec(path)
    body = spec['body']

    http_buff = b'HTTP/1.1 200 OK\r\n'
    for name, value in spec['headers']:
        http_buff += (name + ': ' + value + '\r\n').encode('utf-8')
    http_buff += b'\r\n'

    block = http_buff + body

    warc_date = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    warc_buff = (
        'WARC/1.0\r\n'
        'WARC-Type: response\r\n'
        'WARC-Target-URI: ' + url + '\r\n'
        'WARC-Date: ' + warc_date + '\r\n'
        'Content-Type: application/http; msgtype=response\r\n'
        'Content-Length: ' + str(len(block)) + '\r\n\r\n'
    ).encode('utf-8')

    outer_headers = [('Content-Type', 'application/warc-record'),
                     ('WARC-Target-URI', url)]

    start_response('200 OK', outer_headers)

    delay = spec.get('stream_delay')
    if not delay:
        return [warc_buff + block]

    third = max(1, len(body) // 3)
    chunks = [body[0:third], body[third:2 * third], body[2 * third:]]

    def generate():
        STREAM_EVENTS.append((time.time(), 'head'))
        yield warc_buff + http_buff
        for index, chunk in enumerate(chunks):
            gevent.sleep(delay)
            STREAM_EVENTS.append((time.time(), 'emit', index, len(chunk)))
            yield chunk
        STREAM_EVENTS.append((time.time(), 'end'))

    return generate()


# ============================================================================
def policy(value='REDACTED'):
    return JsonRedactPolicy.from_config([
        {'url_filter': r'/api/',
         'pointers': ['/secret', '/nested/token', '/items/1'],
         'value': value},
    ])


REDACTED_USER = {
    "name": "Ann",
    "secret": "REDACTED",
    "items": ["keep0", "REDACTED"],
    "nested": {"token": "REDACTED", "ok": True},
}


def sha1_b32(data):
    return 'sha1:' + base64.b32encode(hashlib.sha1(data).digest()).decode('ascii').rstrip('=')


def snapshot_records(dirpath):
    """Read every WARC record in dirpath and snapshot it while iterating.

    warcio drains a record's payload stream when advancing to the next one,
    so payload bytes must be consumed during iteration.
    """
    snapshots = []
    if not os.path.isdir(dirpath):
        return snapshots
    for filename in sorted(os.listdir(dirpath)):
        with open(os.path.join(dirpath, filename), 'rb') as fh:
            for record in ArchiveIterator(fh):
                snapshots.append({
                    'rec_type': record.rec_type,
                    'rec_headers': record.rec_headers,
                    'http_headers': record.http_headers,
                    'payload': record.raw_stream.read(),
                })
    return snapshots


def check_entity_consistency(snapshot):
    payload = snapshot['payload']
    assert snapshot['rec_headers'].get_header('WARC-Payload-Digest') == \
        sha1_b32(payload)

    http_headers = snapshot['http_headers']
    if http_headers is not None:
        headers_buff = http_headers.to_ascii_bytes()
        assert snapshot['rec_headers'].get_header('WARC-Block-Digest') == \
            sha1_b32(headers_buff + payload)

        assert int(snapshot['rec_headers'].get_header('Content-Length')) == \
            len(headers_buff) + len(payload)

        content_length = http_headers.get_header('Content-Length')
        if content_length is not None:
            assert content_length == str(len(payload))

    return payload


def find_response(dirpath, url):
    for snapshot in snapshot_records(dirpath):
        if (snapshot['rec_type'] == 'response' and
                snapshot['rec_headers'].get_header('WARC-Target-URI') == url):
            return snapshot
    return None


# ============================================================================
class TestJsonRedactionRecorder(TempDirTests, BaseTestClass):
    @classmethod
    def setup_class(cls):
        super(TestJsonRedactionRecorder, cls).setup_class()
        cls.upstream_server = GeventServer(controlled_upstream)
        cls.upstream_url = 'http://localhost:{0}'.format(cls.upstream_server.port)
        cls.warcs_dir = to_path(cls.root_dir + '/warcs')
        os.makedirs(cls.warcs_dir)

    @classmethod
    def teardown_class(cls):
        cls.upstream_server.stop()
        super(TestJsonRedactionRecorder, cls).teardown_class()

    def _recorder(self, name, json_redact):
        dirpath = to_path(self.root_dir + '/warcs/' + name + '/')
        writer = PerRecordWARCWriter(dirpath)
        recorder = RecorderApp(self.upstream_url, writer, json_redact=json_redact)
        return recorder, webtest.TestApp(recorder), dirpath.rstrip(os.path.sep)

    def _record(self, recorder, testapp, target_path, coll=None):
        url = 'http://controlled' + target_path
        req_url = '/live/resource/postreq?url=' + url
        if coll:
            req_url += '&param.recorder.coll=' + coll

        raw = ('GET {0} HTTP/1.1\r\nHost: controlled\r\n\r\n'
               .format(target_path)).encode('utf-8')

        resp = testapp.post(req_url, raw)
        result = self._drain(recorder)
        return resp, result, url

    @staticmethod
    def _drain(recorder):
        # the background write loop may consume the entry first; either way
        # the observable counters/files reflect the outcome
        if recorder.write_queue.empty():
            return None
        return recorder._write_one()

    @staticmethod
    def _assert_result(result, expected, recorder):
        if result is not None:
            assert result == expected
        assert recorder.record_counts[expected] == 1

    def test_identity_redaction(self):
        recorder, testapp, dirpath = self._recorder('identity', policy())

        resp, result, url = self._record(recorder, testapp, '/api/user')

        # browser receives the untouched upstream response
        assert b'TOPSECRET' in resp.body
        self._assert_result(result, RecorderApp.RESULT_REDACTED, recorder)

        records = snapshot_records(dirpath)
        assert [r['rec_type'] for r in records] == ['response', 'request']

        stored = find_response(dirpath, url)
        payload = check_entity_consistency(stored)

        assert json.loads(payload.decode('utf-8')) == REDACTED_USER
        assert b'TOPSECRET' not in payload
        assert b'TKN' not in payload

    def test_gzip_redaction(self):
        recorder, testapp, dirpath = self._recorder('gzip', policy())

        resp, result, url = self._record(recorder, testapp, '/api/user-gz')

        # browser still got the original gzipped entity
        assert USER_JSON_GZ in resp.body
        self._assert_result(result, RecorderApp.RESULT_REDACTED, recorder)

        stored = find_response(dirpath, url)
        payload = check_entity_consistency(stored)

        assert stored['http_headers'].get_header('Content-Encoding') == 'gzip'
        decoded = gzip.decompress(payload)
        assert json.loads(decoded.decode('utf-8')) == REDACTED_USER
        assert b'TOPSECRET' not in decoded

    def test_identity_redaction_deterministic(self):
        recorder, testapp, dirpath = self._recorder('det', policy())

        _, result1, url = self._record(recorder, testapp, '/api/user')
        _, result2, _ = self._record(recorder, testapp, '/api/user')

        if result1 is not None:
            assert result1 == RecorderApp.RESULT_REDACTED
        if result2 is not None:
            assert result2 == RecorderApp.RESULT_REDACTED
        assert recorder.record_counts['redacted'] == 2

        payloads = [r['payload'] for r in snapshot_records(dirpath)
                    if r['rec_type'] == 'response']
        assert len(payloads) == 2
        assert payloads[0] == payloads[1]

    def test_gzip_redaction_deterministic(self):
        recorder, testapp, dirpath = self._recorder('gzdet', policy())

        self._record(recorder, testapp, '/api/user-gz')
        self._record(recorder, testapp, '/api/user-gz')

        payloads = [r['payload'] for r in snapshot_records(dirpath)
                    if r['rec_type'] == 'response']
        assert len(payloads) == 2
        assert payloads[0] == payloads[1]
        assert gzip.decompress(payloads[0]) != USER_JSON

    def test_content_md5_recomputed(self):
        recorder, testapp, dirpath = self._recorder('md5', policy())

        _, result, url = self._record(recorder, testapp, '/api/user-md5')
        self._assert_result(result, RecorderApp.RESULT_REDACTED, recorder)

        stored = find_response(dirpath, url)
        payload = check_entity_consistency(stored)
        expected_md5 = base64.b64encode(hashlib.md5(payload).digest()).decode('ascii')
        assert stored['http_headers'].get_header('Content-MD5') == expected_md5
        assert stored['http_headers'].get_header('Content-MD5') != \
            base64.b64encode(hashlib.md5(USER_JSON).digest()).decode('ascii')

    def test_missing_charset_defaults_to_utf8(self):
        recorder, testapp, dirpath = self._recorder('nocharset', policy())

        _, result, url = self._record(recorder, testapp, '/api/user-nocharset')
        self._assert_result(result, RecorderApp.RESULT_REDACTED, recorder)
        stored = find_response(dirpath, url)
        assert json.loads(stored['payload'].decode('utf-8')) == REDACTED_USER

    def test_empty_body_unchanged(self):
        recorder, testapp, dirpath = self._recorder('empty', policy())

        _, result, url = self._record(recorder, testapp, '/api/empty')
        self._assert_result(result, RecorderApp.RESULT_WRITTEN, recorder)
        stored = find_response(dirpath, url)
        assert stored['payload'] == b''

    def test_non_json_in_scope_unchanged(self):
        recorder, testapp, dirpath = self._recorder('html', policy())

        resp, result, url = self._record(recorder, testapp, '/api/html')
        assert b'TOPSECRET' in resp.body
        self._assert_result(result, RecorderApp.RESULT_WRITTEN, recorder)

        stored = find_response(dirpath, url)
        assert stored['payload'] == b'<html>TOPSECRET</html>'

    def test_out_of_scope_unchanged(self):
        recorder, testapp, dirpath = self._recorder('scope', policy())

        _, result, url = self._record(recorder, testapp, '/other/user')
        self._assert_result(result, RecorderApp.RESULT_WRITTEN, recorder)

        stored = find_response(dirpath, url)
        assert stored['payload'] == USER_JSON

    @pytest.mark.parametrize('path,reason,marker', [
        ('/api/badgzip', 'invalid_gzip', b'NOT-GZIP-TOPSECRET'),
        ('/api/truncgz', 'invalid_gzip', None),
        ('/api/badjson', 'invalid_json', b'TOPSECRET'),
        ('/api/badenc', 'unsupported_content_encoding', b'br-br-TOPSECRET'),
        ('/api/badcharset', 'unsupported_charset', 'TOPSECRET'.encode('utf-16-le')),
    ])
    def test_processing_failure_drops_capture(self, path, reason, marker):
        recorder, testapp, dirpath = self._recorder('fail-' + path.strip('/'),
                                                    policy())

        resp, result, url = self._record(recorder, testapp, path)

        # client still receives the original upstream entity
        assert resp.status_int == 200
        if marker is not None:
            assert marker in resp.body

        # capture is not archived and the failure is determinable
        if result is not None:
            assert result == RecorderApp.RESULT_REDACTION_FAILED
        assert recorder.record_counts['redaction_failed'] == 1
        failure = recorder.redaction_failures[-1]
        assert failure['url'] == url
        assert failure['reason'] == reason

        assert not os.path.isdir(dirpath) or os.listdir(dirpath) == []
        assert find_response(dirpath, url) is None

    def test_disabled_keeps_original_recording(self):
        recorder, testapp, dirpath = self._recorder('disabled', None)

        resp, result, url = self._record(recorder, testapp, '/api/user')
        assert b'TOPSECRET' in resp.body
        self._assert_result(result, RecorderApp.RESULT_WRITTEN, recorder)
        assert recorder.record_counts['redacted'] == 0
        assert recorder.record_counts['redaction_failed'] == 0

        stored = find_response(dirpath, url)
        payload = check_entity_consistency(stored)
        assert json.loads(payload.decode('utf-8')) == USER

    def test_streaming_large_body(self):
        dirpath = to_path(self.root_dir + '/warcs/stream/')
        writer = PerRecordWARCWriter(dirpath)
        recorder = RecorderApp(self.upstream_url, writer, json_redact=policy())
        recorder_server = GeventServer(recorder)
        dirpath = dirpath.rstrip(os.path.sep)

        url = 'http://controlled/api/big'
        record_url = 'http://localhost:{0}/live/resource/postreq?url={1}'.format(
            recorder_server.port, url)
        raw = b'GET /api/big HTTP/1.1\r\nHost: controlled\r\n\r\n'

        del STREAM_EVENTS[:]

        resp = requests.post(record_url, data=raw, stream=True)
        assert resp.status_code == 200

        arrival_times = []
        chunks = []
        for chunk in resp.iter_content(4096):
            if chunk:
                arrival_times.append(time.time())
                chunks.append(chunk)
        resp.close()

        # server emitted body chunks 0.4s apart: data must have reached the
        # client while the upstream response was still being produced
        emit_times = [event[0] for event in STREAM_EVENTS if event[1] == 'emit']
        assert len(emit_times) == 3
        assert arrival_times[0] < emit_times[2] - 0.1

        browser_body = b''.join(chunks)
        assert b'TOPSECRET' in browser_body

        # let the recorder's response wrapper finish and queue the capture
        for _ in range(50):
            if not recorder.write_queue.empty() or \
                    recorder.record_counts['redacted'] or \
                    recorder.record_counts['redaction_failed']:
                break
            gevent.sleep(0.05)

        self._drain(recorder)
        assert recorder.record_counts['redaction_failed'] == 0, \
            list(recorder.redaction_failures)
        assert recorder.record_counts['redacted'] == 1

        stored = find_response(dirpath, url)
        payload = check_entity_consistency(stored)
        assert len(payload) > 512 * 1024
        document = json.loads(payload.decode('utf-8'))
        assert document['secret'] == 'REDACTED'
        assert len(document['pad']) == 600000
        assert b'TOPSECRET' not in payload

        recorder_server.stop()


# ============================================================================
class TestJsonRedactionDedup(FakeRedisTests, TempDirTests, BaseTestClass):
    COLL = 'COLL'

    @classmethod
    def setup_class(cls):
        super(TestJsonRedactionDedup, cls).setup_class()
        cls.upstream_server = GeventServer(controlled_upstream)
        cls.upstream_url = 'http://localhost:{0}'.format(cls.upstream_server.port)
        cls.warcs_dir = to_path(cls.root_dir + '/warcs')
        os.makedirs(cls.warcs_dir)
        cls.index = WritableRedisIndexer(
            redis_url='redis://localhost/2/{coll}:cdxj',
            file_key_template='{coll}:warc',
            rel_path_template=cls.warcs_dir + os.path.sep,
            dupe_policy=WriteRevisitDupePolicy())
        cls.redis = FakeStrictRedis.from_url('redis://localhost/2')

    @classmethod
    def teardown_class(cls):
        cls.upstream_server.stop()
        super(TestJsonRedactionDedup, cls).teardown_class()

    def _recorder(self, name, json_redact):
        dirpath = to_path(self.root_dir + '/warcs/' + name + '/')
        writer = PerRecordWARCWriter(dirpath, dedup_index=self.index)
        recorder = RecorderApp(self.upstream_url, writer, json_redact=json_redact)
        return recorder, webtest.TestApp(recorder), dirpath.rstrip(os.path.sep)

    def _record(self, recorder, testapp, target_path):
        url = 'http://controlled' + target_path
        req_url = '/live/resource/postreq?url={0}&param.recorder.coll={1}'.format(
            url, self.COLL)
        raw = ('GET {0} HTTP/1.1\r\nHost: controlled\r\n\r\n'
               .format(target_path)).encode('utf-8')
        resp = testapp.post(req_url, raw)
        if not recorder.write_queue.empty():
            recorder._write_one()
        return resp, None, url

    def _cdx(self, url):
        entries = self.redis.zrange(self.COLL + ':cdxj', 0, -1)
        result = [CDXObject(entry) for entry in entries
                  if CDXObject(entry)['url'] == url]
        return result

    def test_repeat_recording_creates_revisit_of_redacted_payload(self):
        recorder, testapp, dirpath = self._recorder('repeat', policy('AAA'))

        self._record(recorder, testapp, '/api/user')
        self._record(recorder, testapp, '/api/user')

        cdx_list = self._cdx('http://controlled/api/user')
        assert len(cdx_list) == 2

        response_cdx = [c for c in cdx_list if c['mime'] == 'application/json']
        revisit_cdx = [c for c in cdx_list if c['mime'] == 'warc/revisit']
        assert len(response_cdx) == 1
        assert len(revisit_cdx) == 1
        assert revisit_cdx[0]['digest'] == response_cdx[0]['digest']

        redacted_digest = response_cdx[0]['digest']

        snapshots = snapshot_records(dirpath)

        # the stored full response carries the redaction, not the original
        stored = [s for s in snapshots if s['rec_type'] == 'response'][0]
        assert sha1_b32(stored['payload']) == 'sha1:' + redacted_digest
        assert json.loads(stored['payload'].decode('utf-8'))['secret'] == 'AAA'
        assert b'TOPSECRET' not in stored['payload']

        revisits = [s for s in snapshots if s['rec_type'] == 'revisit']
        assert len(revisits) == 1
        revisit = revisits[0]
        assert revisit['rec_headers'].get_header('WARC-Payload-Digest') == \
            'sha1:' + redacted_digest
        assert revisit['rec_headers'].get_header('WARC-Refers-To-Target-URI') == \
            'http://controlled/api/user'
        assert revisit['rec_headers'].get_header('WARC-Refers-To-Date') == \
            timestamp_to_iso_date(response_cdx[0]['timestamp'])

    def test_changing_rules_records_new_entity_with_new_digest(self):
        rec_a, app_a, dir_a = self._recorder('rule-a', policy('AAA'))
        self._record(rec_a, app_a, '/api/user-gz')

        cdx_a = self._cdx('http://controlled/api/user-gz')
        assert len(cdx_a) == 1
        digest_a = cdx_a[0]['digest']

        rec_b, app_b, dir_b = self._recorder('rule-b', policy('BBB'))
        self._record(rec_b, app_b, '/api/user-gz')

        cdx_all = self._cdx('http://controlled/api/user-gz')
        assert len(cdx_all) == 2
        digests = sorted(c['digest'] for c in cdx_all)
        assert digests[0] != digests[1]
        assert digest_a in digests

        response_b = [s for s in snapshot_records(dir_b)
                      if s['rec_type'] == 'response'][0]
        payload_b = gzip.decompress(response_b['payload'])
        assert json.loads(payload_b.decode('utf-8'))['secret'] == 'BBB'

        response_a = [s for s in snapshot_records(dir_a)
                      if s['rec_type'] == 'response'][0]
        payload_a = gzip.decompress(response_a['payload'])
        assert json.loads(payload_a.decode('utf-8'))['secret'] == 'AAA'

        # a new-rule digest must never resolve to the old-rule capture
        iso_dt = timestamp_to_iso_date(cdx_all[0]['timestamp'])
        params = {'param.recorder.coll': self.COLL}
        found = self.index.lookup_revisit(params, 'sha1:' + digest_a,
                                          'http://controlled/api/user-gz', iso_dt)
        assert found is not None
        assert found[1] == 'http://controlled/api/user-gz'
        assert found[2] == timestamp_to_iso_date(cdx_a[0]['timestamp'])

        missing = self.index.lookup_revisit(
            params, 'sha1:' + '0' * len(digest_a),
            'http://controlled/api/user-gz', iso_dt)
        assert missing is None

    def test_revisit_after_enabling_redaction_cannot_reach_original(self):
        url = 'http://controlled/api/dup'

        # first recording: redaction disabled, original payload archived
        rec_off, app_off, dir_off = self._recorder('off', None)
        self._record(rec_off, app_off, '/api/dup')

        cdx_after_off = self._cdx(url)
        assert len(cdx_after_off) == 1
        original_ts = cdx_after_off[0]['timestamp']
        original_digest = cdx_after_off[0]['digest']

        original_record = [s for s in snapshot_records(dir_off)
                           if s['rec_type'] == 'response'][0]
        assert b'TOPSECRET' in original_record['payload']

        # make sure the redacted capture gets a distinct timestamp
        time.sleep(1.05)

        # enable redaction and record twice: one full redacted capture and one
        # revisit that must refer to the redacted capture, never the original
        rec_on, app_on, dir_on = self._recorder('on', policy('CCC'))

        self._record(rec_on, app_on, '/api/dup')
        self._record(rec_on, app_on, '/api/dup')

        cdx_all = self._cdx(url)
        assert len(cdx_all) == 3

        full = [c for c in cdx_all if c['mime'] == 'application/json']
        revisits = [c for c in cdx_all if c['mime'] == 'warc/revisit']
        assert len(full) == 2
        assert len(revisits) == 1

        redacted_cdx = [c for c in full if c['digest'] != original_digest]
        assert len(redacted_cdx) == 1
        redacted_ts = redacted_cdx[0]['timestamp']
        redacted_digest = redacted_cdx[0]['digest']
        assert redacted_ts != original_ts

        on_snapshots = snapshot_records(dir_on)
        redacted_records = [s for s in on_snapshots
                            if s['rec_type'] == 'response']
        assert len(redacted_records) == 1
        redacted_payload = redacted_records[0]['payload']
        assert sha1_b32(redacted_payload) == 'sha1:' + redacted_digest
        assert json.loads(redacted_payload.decode('utf-8'))['secret'] == 'CCC'
        assert b'TOPSECRET' not in redacted_payload

        revisit = [s for s in on_snapshots if s['rec_type'] == 'revisit'][0]
        assert revisit['rec_headers'].get_header('WARC-Payload-Digest') == \
            'sha1:' + redacted_digest
        assert revisit['rec_headers'].get_header('WARC-Refers-To-Date') == \
            timestamp_to_iso_date(redacted_ts)
        assert revisit['rec_headers'].get_header('WARC-Refers-To-Date') != \
            timestamp_to_iso_date(original_ts)

        # resolving the revisit yields the redacted entity
        refers_to_date = revisit['rec_headers'].get_header('WARC-Refers-To-Date')
        referenced = [s for s in on_snapshots
                      if s['rec_type'] == 'response'
                      and s['rec_headers'].get_header('WARC-Date') == refers_to_date]
        assert len(referenced) == 1
        assert sha1_b32(referenced[0]['payload']) == 'sha1:' + redacted_digest
        assert b'TOPSECRET' not in referenced[0]['payload']

        # the original digest can never match a redacted-rule capture
        params = {'param.recorder.coll': self.COLL}
        iso_dt = timestamp_to_iso_date(redacted_ts)
        result = self.index.lookup_revisit(params, 'sha1:' + redacted_digest,
                                           url, iso_dt)
        assert result is not None
        assert result[2] == timestamp_to_iso_date(redacted_ts)
        assert result[2] != timestamp_to_iso_date(original_ts)
