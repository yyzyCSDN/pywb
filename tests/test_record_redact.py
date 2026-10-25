import gzip
import json
import os
import time

from mock import patch
from fakeredis import FakeStrictRedis

from warcio import ArchiveIterator

from .base_config_test import BaseConfigTest, CollsDirMixin
from pywb.manager.manager import main as manager
from pywb.manager.autoindex import AutoIndexer
from pywb.utils.geventserver import GeventServer
from pywb.warcserver.index.cdxobject import CDXObject
from pywb.warcserver.test.testutils import (
    FakeRedisTests,
    HttpBinLiveTests,
    BaseTestClass,
)


# ============================================================================
# Controlled origin serving unprocessable / good JSON entities directly.
# ============================================================================
def origin_app(environ, start_response):
    path = environ.get('PATH_INFO', '')

    if path == '/api/badjson':
        start_response('200 OK', [('Content-Type', 'application/json')])
        return [b'{ "secret": "ORIGIN-SECRET", broken']

    if path == '/api/good':
        body = json.dumps({'secret': 'ORIGIN-SECRET', 'name': 'ok'}).encode('utf-8')
        start_response('200 OK', [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(body))),
        ])
        return [body]

    start_response('404 Not Found', [('Content-Type', 'text/plain')])
    return [b'not found']


# ============================================================================
REDACT_CONFIG = {
    'recorder': {
        'source_coll': 'live',
        'enable_put_custom_record': True,
        'json_redact': [
            {
                'url_filter': r'httpbin\.org/get\?',
                'pointers': ['/args/secret'],
                'value': 'REDACTED',
            },
            {
                'url_filter': r'httpbin\.org/gzip$',
                'pointers': ['/gzipped'],
                'value': False,
            },
            {
                'url_filter': r'origin\.test/api/',
                'pointers': ['/secret'],
                'value': 'REDACTED',
            },
        ],
    },
}


def snapshot_responses(coll_dir):
    """Return (url, payload_digest, payload, content_encoding) for every
    stored response record in a collection archive directory.
    """
    archive = os.path.join(coll_dir, 'archive')
    responses = []
    if not os.path.isdir(archive):
        return responses

    for filename in sorted(os.listdir(archive)):
        if not filename.endswith('.warc.gz'):
            continue
        with open(os.path.join(archive, filename), 'rb') as fh:
            for record in ArchiveIterator(fh):
                if record.rec_type == 'response':
                    responses.append({
                        'url': record.rec_headers.get_header('WARC-Target-URI'),
                        'digest': record.rec_headers.get_header(
                            'WARC-Payload-Digest'),
                        'payload': record.raw_stream.read(),
                        'content_encoding': record.http_headers.get_header(
                            'Content-Encoding'),
                    })
    return responses


# ============================================================================
class TestRecordRedact(HttpBinLiveTests, CollsDirMixin, BaseConfigTest):
    @classmethod
    def setup_class(cls):
        super(TestRecordRedact, cls).setup_class(
            'config_test_record.yaml', custom_config=REDACT_CONFIG)

        # controlled origin for non-httpbin failure/success cases
        cls.origin_server = GeventServer(origin_app)
        origin_local = 'http://localhost:{0}/'.format(cls.origin_server.port)

        def get_load_url(self, params):
            url = params['url']
            url = url.replace('http://test.httpbin.org/', cls.httpbin_local)
            url = url.replace('http://httpbin.org/', cls.httpbin_local)
            url = url.replace('https://httpbin.org/', cls.httpbin_local)
            url = url.replace('http://origin.test/', origin_local)
            return url

        cls.combined_mock = patch(
            'pywb.warcserver.index.indexsource.LiveIndexSource.get_load_url',
            get_load_url)
        cls.combined_mock.start()

        manager(['init', 'test'])
        cls.indexer = AutoIndexer(interval=0.1)
        cls.indexer.start()

    @classmethod
    def teardown_class(cls):
        cls.indexer.stop()
        cls.combined_mock.stop()
        cls.origin_server.stop()
        super(TestRecordRedact, cls).teardown_class()

    def coll_dir(self):
        return os.path.join(self.root_dir, '_test_colls', 'test')

    def ensure_empty(self):
        while not self.app.recorder.write_queue.empty():
            time.sleep(0.05)
        time.sleep(0.4)

    def responses_for(self, url):
        return [r for r in snapshot_responses(self.coll_dir())
                if r['url'] == url]

    def test_01_browser_gets_original_archive_gets_redacted(self):
        res = self.testapp.get(
            '/test/record/mp_/http://httpbin.org/get?secret=S123')
        # browser receives the live, unmodified upstream entity
        assert '"secret": "S123"' in res.text

        self.ensure_empty()

        stored = self.responses_for('http://httpbin.org/get?secret=S123')
        assert len(stored) == 1
        document = json.loads(stored[0]['payload'].decode('utf-8'))
        assert document['args'] == {'secret': 'REDACTED'}
        assert b'"secret": "S123"' not in stored[0]['payload']

    def test_02_replay_serves_redacted_entity(self):
        self.ensure_empty()
        res = self.testapp.get(
            '/test/mp_/http://httpbin.org/get?secret=S123')
        assert res.json['args'] == {'secret': 'REDACTED'}
        assert '"secret": "S123"' not in res.text

    def test_03_cdx_digest_matches_redacted_entity(self):
        res = self.testapp.get(
            '/test/cdx?url=http://httpbin.org/get?secret=S123&output=json')
        lines = [json.loads(line) for line in res.text.rstrip().split('\n')]
        assert len(lines) >= 1
        cdx = lines[-1]

        stored = self.responses_for('http://httpbin.org/get?secret=S123')[0]
        assert cdx['digest'] == stored['digest'].split(':', 1)[1]

    def test_04_gzip_entity_redacted_and_replays(self):
        url = 'http://httpbin.org/gzip'
        res = self.testapp.get('/test/record/mp_/' + url)
        assert res.status_int == 200
        self.ensure_empty()

        stored = self.responses_for(url)
        assert len(stored) == 1
        assert stored[0]['content_encoding'] == 'gzip'
        decoded = gzip.decompress(stored[0]['payload'])
        assert json.loads(decoded.decode('utf-8'))['gzipped'] is False

        res = self.testapp.get('/test/mp_/' + url)
        body = res.body
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
        assert json.loads(body.decode('utf-8'))['gzipped'] is False

    def test_05_repeated_recording_replays_redacted(self):
        url = 'http://httpbin.org/get?secret=REPEAT'
        for _ in range(3):
            res = self.testapp.get('/test/record/mp_/' + url)
            assert '"secret": "REPEAT"' in res.text

        self.ensure_empty()

        stored = self.responses_for(url)
        assert len(stored) == 3
        digests = {r['digest'] for r in stored}
        assert len(digests) == 1
        for record in stored:
            assert b'"secret": "REPEAT"' not in record['payload']
            assert b'"secret": "REDACTED"' in record['payload']

        res = self.testapp.get('/test/mp_/' + url)
        assert res.json['args'] == {'secret': 'REDACTED'}

    def test_06_controlled_failure_not_archived(self):
        url = 'http://origin.test/api/badjson'
        res = self.testapp.get('/test/record/mp_/' + url)
        # browser still receives the original upstream bytes
        assert res.status_int == 200
        assert b'ORIGIN-SECRET' in res.body

        self.ensure_empty()

        recorder = self.app.recorder
        assert recorder.record_counts['redaction_failed'] >= 1
        failure = recorder.redaction_failures[-1]
        assert failure['url'] == url
        assert failure['reason'] == 'invalid_json'

        assert self.responses_for(url) == []

        res = self.testapp.get('/test/cdx?url=' + url + '&output=json')
        assert res.text.strip() == ''

    def test_07_controlled_good_entity_redacted(self):
        url = 'http://origin.test/api/good'
        res = self.testapp.get('/test/record/mp_/' + url)
        assert b'ORIGIN-SECRET' in res.body

        self.ensure_empty()

        stored = self.responses_for(url)
        assert len(stored) == 1
        document = json.loads(stored[0]['payload'].decode('utf-8'))
        assert document == {'secret': 'REDACTED', 'name': 'ok'}
        assert b'ORIGIN-SECRET' not in stored[0]['payload']

        res = self.testapp.get('/test/mp_/' + url)
        assert res.json == {'secret': 'REDACTED', 'name': 'ok'}


# ============================================================================
class TestRecordRedactDisabled(HttpBinLiveTests, CollsDirMixin, BaseConfigTest):
    @classmethod
    def setup_class(cls):
        super(TestRecordRedactDisabled, cls).setup_class(
            'config_test_record.yaml')
        manager(['init', 'plain'])
        cls.indexer = AutoIndexer(interval=0.1)
        cls.indexer.start()

    @classmethod
    def teardown_class(cls):
        cls.indexer.stop()
        super(TestRecordRedactDisabled, cls).teardown_class()

    def test_recording_unchanged_when_redaction_off(self):
        assert self.app.recorder.json_redact is None

        res = self.testapp.get(
            '/plain/record/mp_/http://httpbin.org/get?secret=PLAIN')
        assert '"secret": "PLAIN"' in res.text

        while not self.app.recorder.write_queue.empty():
            time.sleep(0.05)
        time.sleep(0.4)

        coll_dir = os.path.join(self.root_dir, '_test_colls', 'plain')
        stored = [r for r in snapshot_responses(coll_dir)
                  if r['url'] == 'http://httpbin.org/get?secret=PLAIN']
        assert len(stored) == 1
        assert b'PLAIN' in stored[0]['payload']

        res = self.testapp.get(
            '/plain/mp_/http://httpbin.org/get?secret=PLAIN')
        assert res.json['args'] == {'secret': 'PLAIN'}


# ============================================================================
class TestRecordRedactRevisit(HttpBinLiveTests, CollsDirMixin, BaseConfigTest,
                              FakeRedisTests, BaseTestClass):
    @classmethod
    def setup_class(cls):
        custom_config = {
            'recorder': {
                'source_coll': 'live',
                'dedup_policy': 'revisit',
                'json_redact': [
                    {
                        'url_filter': r'httpbin\.org/get\?',
                        'pointers': ['/args/secret'],
                        'value': 'REDACTED',
                    },
                ],
            },
        }
        super(TestRecordRedactRevisit, cls).setup_class(
            'config_test_record_dedup.yaml', custom_config=custom_config)
        cls.redis = FakeStrictRedis.from_url('redis://localhost/0')
        manager(['init', 'dedup'])
        cls.indexer = AutoIndexer(interval=0.1)
        cls.indexer.start()

    @classmethod
    def teardown_class(cls):
        cls.indexer.stop()
        super(TestRecordRedactRevisit, cls).teardown_class()

    def test_repeated_capture_becomes_redacted_revisit(self):
        url = 'http://httpbin.org/get?secret=DEDUP'

        for _ in range(2):
            res = self.testapp.get(
                '/dedup/record/mp_/' + url,
                headers={'Referer': 'http://httpbin.org/'})
            assert '"secret": "DEDUP"' in res.text

        while not self.app.recorder.write_queue.empty():
            time.sleep(0.05)
        time.sleep(0.4)

        entries = self.redis.zrange('pywb:dedup:cdxj', 0, -1)
        cdx = [CDXObject(e) for e in entries]
        cdx = [c for c in cdx if c['url'] == url]
        assert len(cdx) == 2

        full = [c for c in cdx if c['mime'] == 'application/json']
        revisit = [c for c in cdx if c['mime'] == 'warc/revisit']
        assert len(full) == 1
        assert len(revisit) == 1
        assert full[0]['digest'] == revisit[0]['digest']

        coll_dir = os.path.join(self.root_dir, '_test_colls', 'dedup')
        stored = snapshot_responses(coll_dir)
        matching = [r for r in stored if r['url'] == url]
        assert len(matching) == 1
        assert b'"secret": "REDACTED"' in matching[0]['payload']
        assert b'"secret": "DEDUP"' not in matching[0]['payload']
        assert revisit[0]['digest'] == \
            matching[0]['digest'].split(':', 1)[1]

        # replay (also resolving the revisit) yields the redacted entity
        res = self.testapp.get('/dedup/mp_/' + url)
        assert res.json['args'] == {'secret': 'REDACTED'}
