import os
import time
import shutil
import logging

import pytest

from pywb.manager.manager import CollectionsManager
from pywb.manager.batch import (
    BatchManager, BatchError,
    STATE_OPEN, STATE_SEALED, STATE_PUBLISHED, STATE_DISCARDED,
)
from pywb.warcserver.index.cdxobject import CDXObject, FILENAME

TEST_COLLECTION_NAME = 'test-coll'

SAMPLE_WARC = os.path.join('sample_archive', 'warcs', 'example.warc')


def make_coll(collections_path, name=TEST_COLLECTION_NAME):
    manager = CollectionsManager(name, colls_dir=collections_path,
                                 must_exist=False)
    manager.add_collection()
    return manager


@pytest.fixture
def bm(tmp_path):
    make_coll(tmp_path)
    return BatchManager(tmp_path)


# ============================================================================
class TestBatchLifecycle:
    def test_create_batch_layout_and_state(self, bm, tmp_path):
        bdir = bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')

        assert os.path.isdir(os.path.join(bdir, 'archive'))
        assert os.path.isdir(os.path.join(bdir, 'indexes'))

        state_file = os.path.join(bdir, 'batch.yaml')
        assert os.path.isfile(state_file)
        assert bm.get_state(TEST_COLLECTION_NAME, 'b1') == STATE_OPEN

        # public dirs are untouched
        public_archive = os.path.join(
            tmp_path, TEST_COLLECTION_NAME, 'archive')
        assert os.listdir(public_archive) == []

    def test_create_unknown_collection(self, bm):
        with pytest.raises(BatchError):
            bm.create_coll_batch('nope', 'b1')

    def test_create_bad_name(self, bm):
        for bad in ('', 'has space', '1/bad', '-bad'):
            with pytest.raises(BatchError):
                bm.create_coll_batch(TEST_COLLECTION_NAME, bad)

    def test_create_duplicate(self, bm):
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        with pytest.raises(BatchError):
            bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')

    def test_list_batches(self, bm):
        assert bm.list_batches(TEST_COLLECTION_NAME) == []

        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b2')
        assert bm.list_batches(TEST_COLLECTION_NAME) == [
            ('b1', STATE_OPEN), ('b2', STATE_OPEN)]

    def test_list_batches_unknown_coll(self, bm):
        with pytest.raises(BatchError):
            bm.list_batches('nope')

    def test_seal_transitions(self, bm):
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        assert bm.seal_batch(TEST_COLLECTION_NAME, 'b1') is True
        assert bm.get_state(TEST_COLLECTION_NAME, 'b1') == STATE_SEALED

        # state survives a fresh manager instance
        fresh = BatchManager(bm.colls_dir)
        assert fresh.get_state(TEST_COLLECTION_NAME, 'b1') == STATE_SEALED

    @pytest.mark.parametrize('action', ['seal'])
    def test_illegal_transitions(self, bm, action):
        # missing batch
        with pytest.raises(BatchError):
            getattr(bm, action + '_batch')(TEST_COLLECTION_NAME, 'missing')

        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        bm.seal_batch(TEST_COLLECTION_NAME, 'b1')

        # double seal is illegal
        with pytest.raises(BatchError):
            bm.seal_batch(TEST_COLLECTION_NAME, 'b1')

    def test_publish_discard_require_sealed(self, bm):
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')

        with pytest.raises(BatchError):
            bm.publish_batch(TEST_COLLECTION_NAME, 'b1', wait=0)

        with pytest.raises(BatchError):
            bm.discard_batch(TEST_COLLECTION_NAME, 'b1', wait=0)


# ============================================================================
class TestPendingCounter:
    def test_begin_end_counter(self, bm):
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        coll = TEST_COLLECTION_NAME

        assert bm.capture_count(coll, 'b1') == 0
        assert bm.begin_capture(coll, 'b1') == 1
        assert bm.begin_capture(coll, 'b1') == 2
        assert bm.end_capture(coll, 'b1') == 1
        assert bm.end_capture(coll, 'b1') == 0

        pf = bm.pending_file(coll, 'b1')
        assert os.path.isfile(pf)
        assert os.path.isfile(pf + '.lock')

    def test_counter_never_negative(self, bm):
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        coll = TEST_COLLECTION_NAME
        assert bm.end_capture(coll, 'b1') == 0
        assert bm.capture_count(coll, 'b1') == 0

    def test_counter_missing_batch(self, bm):
        with pytest.raises(OSError):
            bm.begin_capture(TEST_COLLECTION_NAME, 'missing')

    def test_wait_drained(self, bm):
        bm.create_coll_batch(TEST_COLLECTION_NAME, 'b1')
        coll = TEST_COLLECTION_NAME

        assert bm.wait_drained(coll, 'b1', timeout=0.1) is True

        bm.begin_capture(coll, 'b1')
        assert bm.wait_drained(coll, 'b1', timeout=0.2, poll=0.05) is False

        def finish():
            time.sleep(0.15)
            bm.end_capture(coll, 'b1')

        import threading
        t = threading.Thread(target=finish)
        t.start()
        try:
            assert bm.wait_drained(coll, 'b1', timeout=2.0, poll=0.05) is True
        finally:
            t.join()


# ============================================================================
class TestBatchPathParsing:
    def test_parse_batch_archive_path(self, bm):
        p = os.path.join('collections', 'my-coll', 'batches',
                         'batch-1', 'archive')
        assert BatchManager.parse_batch_archive_path(p) == \
            ('my-coll', 'batch-1')

        assert BatchManager.parse_batch_archive_path(
            os.path.join('collections', 'my-coll', 'archive')) is None
        assert BatchManager.parse_batch_archive_path('') is None


# ============================================================================
class TestBatchCLI:
    def test_cli_lifecycle(self, tmp_path, monkeypatch, capsys):
        from pywb.manager.manager import main as manager

        # manager.main() reconfigures root logging globally; restore it so
        # later tests in this process keep their default capture format
        saved_handlers = logging.root.handlers[:]
        saved_level = logging.root.level
        try:
            self._run_cli_lifecycle(tmp_path, monkeypatch, capsys, manager)
        finally:
            logging.root.handlers[:] = saved_handlers
            logging.root.setLevel(saved_level)

    def _run_cli_lifecycle(self, tmp_path, monkeypatch, capsys, manager):
        monkeypatch.setattr(CollectionsManager, 'COLLS_DIR', str(tmp_path))

        manager(['init', 'c1'])
        manager(['batch', 'create', 'c1', 'b1'])
        manager(['batch', 'list', 'c1'])
        assert '- b1: open' in capsys.readouterr().out

        shutil.copy2(
            SAMPLE_WARC,
            os.path.join(tmp_path, 'c1', 'batches', 'b1', 'archive',
                         'example.warc'))

        manager(['batch', 'seal', 'c1', 'b1'])
        manager(['batch', 'publish', 'c1', 'b1', '--wait', '0'])
        manager(['batch', 'list', 'c1'])
        out = capsys.readouterr().out
        assert '- b1: published' in out

        # re-publish is reported as idempotent no-op
        manager(['batch', 'publish', 'c1', 'b1', '--wait', '0'])
        assert 'already published' in capsys.readouterr().out

        # discarded batch lifecycle
        manager(['batch', 'create', 'c1', 'b2'])
        manager(['batch', 'seal', 'c1', 'b2'])
        manager(['batch', 'discard', 'c1', 'b2', '--wait', '0'])
        manager(['batch', 'list', 'c1'])
        out = capsys.readouterr().out
        assert '- b2: discarded' in out

        # missing action -> argparse error
        with pytest.raises(SystemExit):
            manager(['batch'])

        # create batch in missing collection -> error
        with pytest.raises(IOError):
            manager(['batch', 'create', 'nope', 'b1'])


# ============================================================================
class TestReservedDirExcludedFromIndexing:
    def _layout(self, bm, tmp_path):
        coll = TEST_COLLECTION_NAME
        coll_dir = os.path.join(tmp_path, coll)
        normal = os.path.join(coll_dir, 'archive', 'normal.warc')
        reserved = os.path.join(coll_dir, 'archive', '.batches',
                                'b1', 'secret.warc')
        os.makedirs(os.path.dirname(reserved))
        shutil.copy2(SAMPLE_WARC, normal)
        shutil.copy2(SAMPLE_WARC, reserved)
        return coll_dir, normal, reserved

    def test_autoindex_skips_reserved_dir(self, bm, tmp_path):
        from pywb.manager.autoindex import AutoIndexer

        coll_dir, normal, reserved = self._layout(bm, tmp_path)

        indexer = AutoIndexer(colls_dir=tmp_path, interval=0,
                              keep_running=False)
        indexer.check_path()

        with open(os.path.join(coll_dir, 'indexes', 'autoindex.cdxj'),
                  'r') as fh:
            text = fh.read()
        assert 'normal.warc' in text
        assert 'secret.warc' not in text
        assert '.batches' not in text

    def test_reindex_skips_reserved_dir(self, bm, tmp_path):
        coll_dir, normal, reserved = self._layout(bm, tmp_path)

        manager = CollectionsManager(TEST_COLLECTION_NAME,
                                     colls_dir=tmp_path, must_exist=True)
        manager.reindex()

        with open(os.path.join(coll_dir, 'indexes', 'index.cdxj'),
                  'r') as fh:
            text = fh.read()
        assert 'normal.warc' in text
        assert 'secret.warc' not in text
        assert '.batches' not in text


# ============================================================================
def make_cdx_line(filename, offset, length):
    cdx = CDXObject()
    cdx['urlkey'] = 'com,example)/x'
    cdx['timestamp'] = '20200101000000'
    cdx['url'] = 'http://example.com/x'
    cdx['offset'] = str(offset)
    cdx['length'] = str(length)
    cdx[FILENAME] = filename
    return cdx.to_cdxj().rstrip('\n').encode('utf-8')


def add_sample_warc(bm, coll, batch, warc_name='example.warc'):
    dest = os.path.join(bm.batch_archive_dir(coll, batch), warc_name)
    shutil.copy2(SAMPLE_WARC, dest)
    return dest


def read_lines(path):
    with open(path, 'rb') as fh:
        return [ln for ln in (raw.rstrip(b'\n') for raw in fh) if ln]


# ============================================================================
class TestBatchPublish:
    def test_publish_moves_payloads_and_atomic_index(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b1')
        warc = add_sample_warc(bm, coll, 'b1')
        bm.seal_batch(coll, 'b1')

        assert bm.publish_batch(coll, 'b1', wait=0) is True

        # payloads live in the reserved public dir as one directory
        pub_archive = bm.pub_batch_archive_dir(coll, 'b1')
        assert os.path.isdir(pub_archive)
        assert os.path.isfile(os.path.join(pub_archive, 'example.warc'))
        assert not os.path.isdir(bm.batch_archive_dir(coll, 'b1'))

        # batch staging archive has been moved, no staging index remains
        assert not os.path.isfile(
            os.path.join(bm.batch_indexes_dir(coll, 'b1'), 'batch.cdxj'))

        # exactly one complete, sorted public index with rewritten filenames
        pub_index = bm.pub_batch_index_file(coll, 'b1')
        lines = read_lines(pub_index)
        assert len(lines) > 0
        names = set()
        for line in lines:
            cdx = CDXObject(cdxline=line)
            assert cdx[FILENAME].replace('/', os.sep).startswith(
                os.path.join('.batches', 'b1') + os.sep)
            names.add(cdx[FILENAME])
        assert names == {'.batches/b1/example.warc'}
        assert lines == sorted(lines)

        # AutoIndexer reserved dir is dot-nested under public archive
        assert os.path.basename(os.path.dirname(pub_archive)) == '.batches'

        assert bm.get_state(coll, 'b1') == STATE_PUBLISHED

        # references resolve and are readable end to end
        for line in lines:
            cdx = CDXObject(cdxline=line)
            payload = os.path.join(
                os.path.dirname(os.path.dirname(pub_archive)),
                cdx[FILENAME].replace('/', os.sep))
            assert os.path.isfile(payload)

    def test_publish_idempotent(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b1')
        add_sample_warc(bm, coll, 'b1')
        bm.seal_batch(coll, 'b1')

        assert bm.publish_batch(coll, 'b1', wait=0) is True
        index_text_1 = open(bm.pub_batch_index_file(coll, 'b1'), 'rb').read()
        warcs_1 = sorted(os.listdir(bm.pub_batch_archive_dir(coll, 'b1')))

        assert bm.publish_batch(coll, 'b1', wait=0) is False
        index_text_2 = open(bm.pub_batch_index_file(coll, 'b1'), 'rb').read()
        warcs_2 = sorted(os.listdir(bm.pub_batch_archive_dir(coll, 'b1')))

        assert index_text_1 == index_text_2
        assert warcs_1 == warcs_2 == ['example.warc']

    def test_publish_reconciles_interrupted_migration(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b1')
        add_sample_warc(bm, coll, 'b1')
        bm.seal_batch(coll, 'b1')
        assert bm.publish_batch(coll, 'b1', wait=0) is True

        original_text = open(bm.pub_batch_index_file(coll, 'b1'), 'rb').read()

        # simulate a crash after migration + index write but before state set
        data = bm._read_state(coll, 'b1')
        data['state'] = STATE_SEALED
        del data['published_at']
        bm._write_state(coll, 'b1', data)

        assert bm.publish_batch(coll, 'b1', wait=0) is True
        assert bm.get_state(coll, 'b1') == STATE_PUBLISHED
        assert open(bm.pub_batch_index_file(coll, 'b1'), 'rb').read() == \
            original_text

    def test_publish_validation_failure_leaves_no_public_trace(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b1')
        add_sample_warc(bm, coll, 'b1')
        bm.seal_batch(coll, 'b1')

        def fail_validation(*args, **kwargs):
            raise BatchError('payload unreadable')

        bm._validate_payload_refs = fail_validation
        with pytest.raises(BatchError):
            bm.publish_batch(coll, 'b1', wait=0)

        assert not os.path.isdir(bm.pub_batch_archive_dir(coll, 'b1'))
        assert not os.path.isfile(bm.pub_batch_index_file(coll, 'b1'))
        assert os.path.isfile(
            os.path.join(bm.batch_archive_dir(coll, 'b1'), 'example.warc'))
        assert bm.get_state(coll, 'b1') == STATE_SEALED

        # retry after the (simulated) problem clears succeeds
        del bm._validate_payload_refs
        assert bm.publish_batch(coll, 'b1', wait=0) is True
        assert bm.get_state(coll, 'b1') == STATE_PUBLISHED

    def test_publish_empty_batch(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'empty')
        bm.seal_batch(coll, 'empty')
        assert bm.publish_batch(coll, 'empty', wait=0) is True
        assert os.path.isfile(bm.pub_batch_index_file(coll, 'empty'))
        assert read_lines(bm.pub_batch_index_file(coll, 'empty')) == []
        assert bm.get_state(coll, 'empty') == STATE_PUBLISHED

    def test_validate_payload_refs_detects_missing_and_truncated(self, tmp_path):
        warc = str(tmp_path / 'x.warc')
        with open(warc, 'wb') as fh:
            fh.write(b'x' * 100)

        lines = [make_cdx_line('x.warc', 0, 100)]
        BatchManager._validate_payload_refs(lines, str(tmp_path))

        # truncate: declared range no longer fully readable
        with open(warc, 'wb') as fh:
            fh.write(b'x' * 50)
        with pytest.raises(BatchError):
            BatchManager._validate_payload_refs(lines, str(tmp_path))

        # missing payload
        os.remove(warc)
        with pytest.raises(BatchError):
            BatchManager._validate_payload_refs(lines, str(tmp_path))


# ============================================================================
class TestBatchDiscard:
    def test_discard_removes_all_payloads(self, bm, tmp_path):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b2')
        add_sample_warc(bm, coll, 'b2')
        bm.begin_capture(coll, 'b2')
        bm.end_capture(coll, 'b2')
        bm.seal_batch(coll, 'b2')

        assert bm.discard_batch(coll, 'b2', wait=0) is True

        bdir = bm.batch_dir(coll, 'b2')
        assert not os.path.isdir(bm.batch_archive_dir(coll, 'b2'))
        assert not os.path.isdir(bm.batch_indexes_dir(coll, 'b2'))
        assert not os.path.isfile(bm.pending_file(coll, 'b2'))
        assert not os.path.isfile(bm.pending_file(coll, 'b2') + '.lock')

        # only the tombstone remains
        assert os.listdir(bdir) == ['batch.yaml']
        assert bm.get_state(coll, 'b2') == STATE_DISCARDED

        # nothing ever entered the public directories
        public = os.path.join(tmp_path, coll)
        assert not os.path.isdir(os.path.join(public, 'archive', '.batches'))
        assert os.listdir(os.path.join(public, 'indexes')) == []

    def test_discard_idempotent(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b2')
        bm.seal_batch(coll, 'b2')
        assert bm.discard_batch(coll, 'b2', wait=0) is True
        assert bm.discard_batch(coll, 'b2', wait=0) is False

    def test_publish_and_discard_wait_for_in_flight(self, bm):
        coll = TEST_COLLECTION_NAME
        bm.create_coll_batch(coll, 'b3')
        bm.begin_capture(coll, 'b3')
        bm.seal_batch(coll, 'b3')

        with pytest.raises(BatchError):
            bm.publish_batch(coll, 'b3', wait=0.05, poll=0.02)
        with pytest.raises(BatchError):
            bm.discard_batch(coll, 'b3', wait=0.05, poll=0.02)
        assert bm.get_state(coll, 'b3') == STATE_SEALED

        bm.end_capture(coll, 'b3')
        assert bm.discard_batch(coll, 'b3', wait=1.0) is True
        assert bm.get_state(coll, 'b3') == STATE_DISCARDED
