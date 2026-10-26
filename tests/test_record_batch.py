import os
import json
import time

from warcio import ArchiveIterator

from .base_config_test import BaseConfigTest, CollsDirMixin
from pywb.manager.manager import main as manager
from pywb.manager.autoindex import AutoIndexer
from pywb.warcserver.test.testutils import HttpBinLiveTests, to_path


# ============================================================================
class TestRecordBatches(HttpBinLiveTests, CollsDirMixin, BaseConfigTest):
    """End-to-end pending-approval batch lifecycle against the full
    FrontEndApp + AutoIndexer stack (local httpbin, no network)."""

    @classmethod
    def setup_class(cls):
        super(TestRecordBatches, cls).setup_class('config_test_record.yaml')
        cls.indexer = AutoIndexer(interval=0.1)
        cls.indexer.start()
        cls.bm = cls.app.recorder.batch_store

    @classmethod
    def teardown_class(cls):
        cls.indexer.stop()
        super(TestRecordBatches, cls).teardown_class()

    # ----- helpers ----------------------------------------------------------
    def _coll_dir(self, name='c'):
        return os.path.join(self.root_dir, '_test_colls', name)

    def _drain(self):
        while not self.app.recorder.write_queue.empty():
            time.sleep(0.05)
        time.sleep(0.5)

    def _cdx(self, pattern='http://httpbin.org/get*'):
        res = self.testapp.get(
            '/c/cdx?url={0}&output=json'.format(pattern))
        text = res.text.rstrip()
        return [json.loads(line) for line in text.split('\n') if line]

    def _wait_cdx_url(self, url_substr, present=True, timeout=10.0):
        deadline = time.time() + timeout
        while True:
            found = any(url_substr in row['url'] for row in self._cdx())
            if found == present:
                return found
            if time.time() > deadline:
                raise AssertionError(
                    'timed out waiting for {0} (present={1}); rows={2}'.
                    format(url_substr, present,
                           [r['url'] for r in self._cdx()]))
            time.sleep(0.2)

    def _replay(self, url, expect_errors=False):
        return self.testapp.get('/c/mp_/' + url,
                                expect_errors=expect_errors)

    def _batch_warc_dir(self, batch):
        return os.path.join(self._coll_dir(), 'batches', batch, 'archive')

    # ----- tests ------------------------------------------------------------
    def test_00_init_and_public_baseline(self):
        manager(['init', 'c'])
        assert os.path.isdir(os.path.join(self._coll_dir(), 'archive'))

        res = self.testapp.get(
            '/c/record/mp_/http://httpbin.org/get?pub=1')
        assert '"pub": "1"' in res.text
        self._drain()
        self._wait_cdx_url('get?pub=1')

        res = self._replay('http://httpbin.org/get?pub=1')
        assert res.status_int == 200
        assert '"pub": "1"' in res.text

        cls = type(self)
        cls.public_files = set(os.listdir(
            os.path.join(self._coll_dir(), 'archive')))
        assert cls.public_files

    def test_01_batch_recording_isolated(self):
        self.bm.create_coll_batch('c', 'b1')

        res = self.testapp.get(
            '/c/record/mp_/http://httpbin.org/get?batch=b1&A=B')
        assert '"A": "B"' in res.text
        self._drain()

        # warc landed in the batch staging dir, not the public archive
        batch_files = os.listdir(self._batch_warc_dir('b1'))
        assert len(batch_files) == 1 and batch_files[0].endswith('.warc.gz')
        assert set(os.listdir(os.path.join(self._coll_dir(), 'archive'))) == \
            type(self).public_files

        # batch param was stripped from the recorded target URI
        warc_path = os.path.join(self._batch_warc_dir('b1'), batch_files[0])
        target_uris = []
        with open(warc_path, 'rb') as fh:
            for record in ArchiveIterator(fh):
                if record.rec_type == 'response':
                    target_uris.append(
                        record.rec_headers.get_header('WARC-Target-URI'))
        assert target_uris == ['http://httpbin.org/get?A=B']

        # not in ordinary CDX, not replayable, public content still works
        assert not any('get?A=B' in row['url'] for row in self._cdx())
        missing = self._replay('http://httpbin.org/get?A=B',
                               expect_errors=True)
        assert missing.status_int == 404

        public = self._replay('http://httpbin.org/get?pub=1')
        assert public.status_int == 200

        # in-flight counter is balanced after the drain
        assert self.bm.capture_count('c', 'b1') == 0

    def test_02_sealed_batch_rejects_new_captures(self):
        self.bm.seal_batch('c', 'b1')
        # let the recorder reaper close batch file handles
        time.sleep(1.3)

        files_before = os.listdir(self._batch_warc_dir('b1'))
        res = self.testapp.get(
            '/c/record/mp_/http://httpbin.org/get?batch=b1&G=H',
            expect_errors=True)
        assert res.status_int >= 400
        self._drain()

        assert os.listdir(self._batch_warc_dir('b1')) == files_before
        assert not any('get?G=H' in row['url'] for row in self._cdx())
        assert self.bm.capture_count('c', 'b1') == 0

        # ordinary recording is unaffected by sealing a batch
        res = self.testapp.get(
            '/c/record/mp_/http://httpbin.org/get?pub=2')
        assert '"pub": "2"' in res.text
        self._drain()
        self._wait_cdx_url('get?pub=2')

    def test_03_publish_makes_batch_visible_atomically_and_idempotently(self):
        assert self.bm.publish_batch('c', 'b1', wait=10.0) is True

        rows = self._wait_rows_with('get?A=B')
        assert len(rows) == 1
        assert rows[0]['source'] == to_path('c/indexes/batch-b1.cdxj')
        assert rows[0]['filename'].replace('/', os.sep).startswith(
            os.path.join('.batches', 'b1') + os.sep)

        # replayable end to end, payloads in reserved public dir
        res = self._replay('http://httpbin.org/get?A=B')
        assert res.status_int == 200
        assert '"A": "B"' in res.text

        pub_archive = os.path.join(self._coll_dir(), 'archive',
                                   '.batches', 'b1')
        assert os.path.isdir(pub_archive)
        staging = os.path.join(self._coll_dir(), 'batches', 'b1', 'archive')
        assert not os.path.isdir(staging)

        # AutoIndexer never indexed the reserved dir
        with open(os.path.join(self._coll_dir(), 'indexes',
                               'autoindex.cdxj'), 'r') as fh:
            auto_text = fh.read()
        assert '.batches' not in auto_text
        assert 'get?A=B' not in auto_text

        # repeat publish is a no-op, no duplicate rows/files
        assert self.bm.publish_batch('c', 'b1', wait=1.0) is False
        assert len(self._wait_rows_with('get?A=B')) == 1

    def test_04_discard_leaves_no_trace(self):
        self.bm.create_coll_batch('c', 'b2')
        res = self.testapp.get(
            '/c/record/mp_/http://httpbin.org/get?batch=b2&X=Y')
        assert '"X": "Y"' in res.text
        self._drain()
        assert os.listdir(self._batch_warc_dir('b2'))

        self.bm.seal_batch('c', 'b2')
        time.sleep(1.3)
        assert self.bm.discard_batch('c', 'b2', wait=10.0) is True

        bdir = os.path.join(self._coll_dir(), 'batches', 'b2')
        assert os.listdir(bdir) == ['batch.yaml']
        assert not any('get?X=Y' in row['url'] for row in self._cdx())
        missing = self._replay('http://httpbin.org/get?X=Y',
                               expect_errors=True)
        assert missing.status_int == 404
        assert not os.path.isdir(
            os.path.join(self._coll_dir(), 'archive', '.batches', 'b2'))

        # discarding again is reported idempotent
        assert self.bm.discard_batch('c', 'b2', wait=1.0) is False

    def test_05_final_state(self):
        rows = self._cdx()
        urls = [row['url'] for row in rows]
        assert any('get?pub=1' in u for u in urls)
        assert any('get?pub=2' in u for u in urls)
        assert any('get?A=B' in u for u in urls)
        assert not any('get?G=H' in u for u in urls)
        assert not any('get?X=Y' in u for u in urls)

        # rejected batches never appear in the public archive
        assert not os.path.exists(
            os.path.join(self._coll_dir(), 'archive', '.batches', 'b2'))

    # ----- wait helper ------------------------------------------------------
    def _wait_rows_with(self, url_substr):
        self._wait_cdx_url(url_substr)
        return [row for row in self._cdx() if url_substr in row['url']]
