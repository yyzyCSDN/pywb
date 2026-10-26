"""
Pending-approval batches for single-process local deployments.

A batch lives *inside* an existing public collection but outside of its
public ``archive/`` and ``indexes/`` directories, so its captures are
invisible to the AutoIndexer, the CDX directory sources and replay until the
batch is published::

    collections/<coll>/batches/<batch>/
        batch.yaml     # state metadata
        archive/       # batch WARCs while recording
        indexes/       # staging CDXJ (generated at publish time)
        .pending       # number of accepted but not fully written captures

State machine: ``open`` -> ``sealed`` -> ``published`` | ``discarded``
"""

import os
import re
import time
import shutil
import tempfile
import datetime

import yaml
import portalocker


# ============================================================================
# Batch states
# ============================================================================
STATE_OPEN = 'open'
STATE_SEALED = 'sealed'
STATE_PUBLISHED = 'published'
STATE_DISCARDED = 'discarded'

# query / recorder param carrying the batch name
BATCH_QUERY_PARAM = 'batch'
RECORDER_BATCH_PARAM = 'param.recorder.batch'


# ============================================================================
class BatchError(ValueError):
    """Invalid batch operation (bad name, illegal state transition, ...)."""
    pass


# ============================================================================
class BatchManager(object):
    BATCH_RX = re.compile(r'^[\w][-\w]*$')

    BATCHES_DIRNAME = 'batches'
    PUB_BATCHES_DIRNAME = '.batches'
    BATCH_ARCHIVE_DIRNAME = 'archive'
    BATCH_INDEXES_DIRNAME = 'indexes'
    BATCH_STATE_FILE = 'batch.yaml'
    PENDING_FILE = '.pending'

    BATCH_INDEX_PREFIX = 'batch-'
    BATCH_INDEX_SUFFIX = '.cdxj'

    def __init__(self, colls_dir):
        # resolved lazily against the current working directory: the recorder
        # app may be constructed before a deployment changes its cwd, and a
        # relative collections root must keep tracking it
        self._colls_dir = colls_dir

    @property
    def colls_dir(self):
        return os.path.abspath(self._colls_dir)

    # ===== paths ============================================================
    def _coll_dir(self, coll):
        return os.path.join(self.colls_dir, coll)

    def _assert_coll_exists(self, coll):
        coll_dir = self._coll_dir(coll)
        if not os.path.isdir(coll_dir):
            msg = 'Collection {0} does not exist'.format(coll)
            raise BatchError(msg)
        return coll_dir

    def _validate_batch_name(self, batch):
        if not batch or not self.BATCH_RX.match(batch):
            raise BatchError('Invalid Batch Name: ' + str(batch))

    def _batches_root(self, coll):
        return os.path.join(self.colls_dir, coll, self.BATCHES_DIRNAME)

    def batch_dir(self, coll, batch):
        return os.path.join(self._batches_root(coll), batch)

    def batch_archive_dir(self, coll, batch):
        return os.path.join(self.batch_dir(coll, batch),
                            self.BATCH_ARCHIVE_DIRNAME)

    def batch_indexes_dir(self, coll, batch):
        return os.path.join(self.batch_dir(coll, batch),
                            self.BATCH_INDEXES_DIRNAME)

    def state_file(self, coll, batch):
        return os.path.join(self.batch_dir(coll, batch),
                            self.BATCH_STATE_FILE)

    def pending_file(self, coll, batch):
        return os.path.join(self.batch_dir(coll, batch),
                            self.PENDING_FILE)

    def pub_batch_archive_dir(self, coll, batch):
        """Public, AutoIndexer-excluded home of published batch WARCs."""
        return os.path.join(self.colls_dir, coll,
                            self.BATCH_ARCHIVE_DIRNAME,
                            self.PUB_BATCHES_DIRNAME, batch)

    def pub_batch_index_file(self, coll, batch):
        return os.path.join(self.colls_dir, coll,
                            self.BATCH_INDEXES_DIRNAME,
                            self.BATCH_INDEX_PREFIX + batch +
                            self.BATCH_INDEX_SUFFIX)

    # ===== state ============================================================
    @staticmethod
    def _utc_now():
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _read_state(self, coll, batch):
        path = self.state_file(coll, batch)
        if not os.path.isfile(path):
            return None
        with open(path, 'rb') as fh:
            data = yaml.safe_load(fh) or {}
        return data

    def get_state(self, coll, batch):
        data = self._read_state(coll, batch)
        return data.get('state') if data else None

    def _write_state(self, coll, batch, data):
        path = self.state_file(coll, batch)
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(path),
            prefix='.' + self.BATCH_STATE_FILE + '.',
            suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                yaml.safe_dump(data, fh, default_flow_style=False)
            os.replace(tmp, path)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def _require_state(self, coll, batch, expected):
        state = self.get_state(coll, batch)
        if state != expected:
            raise BatchError(
                'Batch {0} in collection {1} is {2}, expected {3}'.format(
                    batch, coll, state or 'missing', expected))
        return state

    # ===== lifecycle: create / list / seal ==================================
    def create_coll_batch(self, coll, batch):
        self._validate_batch_name(batch)
        self._assert_coll_exists(coll)

        bdir = self.batch_dir(coll, batch)
        if os.path.exists(bdir):
            raise BatchError(
                'Batch {0} already exists in collection {1}'.format(
                    batch, coll))

        os.makedirs(self.batch_archive_dir(coll, batch))
        os.makedirs(self.batch_indexes_dir(coll, batch))

        self._write_state(coll, batch, {
            'state': STATE_OPEN,
            'batch': batch,
            'collection': coll,
            'created_at': self._utc_now(),
        })

        return bdir

    def list_batches(self, coll):
        self._assert_coll_exists(coll)
        root = self._batches_root(coll)
        result = []
        if not os.path.isdir(root):
            return result
        for name in sorted(os.listdir(root)):
            if not os.path.isdir(os.path.join(root, name)):
                continue
            state = self.get_state(coll, name)
            if state:
                result.append((name, state))
        return result

    def seal_batch(self, coll, batch):
        self._validate_batch_name(batch)
        self._require_state(coll, batch, STATE_OPEN)
        data = self._read_state(coll, batch)
        data['state'] = STATE_SEALED
        data['sealed_at'] = self._utc_now()
        self._write_state(coll, batch, data)
        return True

    # ===== in-flight capture counter =======================================
    def _adjust_pending(self, coll, batch, delta):
        pf = self.pending_file(coll, batch)
        lockf = pf + '.lock'
        with portalocker.Lock(lockf, timeout=10, check_interval=0.05):
            value = 0
            if os.path.isfile(pf):
                with open(pf, 'r', encoding='utf-8') as fh:
                    try:
                        value = int((fh.read() or '0').strip())
                    except ValueError:
                        value = 0

            value = max(0, value + delta)

            fd, tmp = tempfile.mkstemp(
                dir=os.path.dirname(pf),
                prefix='.' + self.PENDING_FILE + '.',
                suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                    fh.write(str(value))
                os.replace(tmp, pf)
            except Exception:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise

            return value

    def begin_capture(self, coll, batch):
        return self._adjust_pending(coll, batch, 1)

    def end_capture(self, coll, batch):
        return self._adjust_pending(coll, batch, -1)

    def capture_count(self, coll, batch):
        pf = self.pending_file(coll, batch)
        lockf = pf + '.lock'
        with portalocker.Lock(lockf, timeout=10, check_interval=0.05):
            if not os.path.isfile(pf):
                return 0
            with open(pf, 'r', encoding='utf-8') as fh:
                try:
                    return max(0, int((fh.read() or '0').strip()))
                except ValueError:
                    return 0

    def wait_drained(self, coll, batch, timeout=30.0, poll=0.1):
        """Wait until no accepted capture is still being written.

        Returns True once the counter is zero, False on timeout.
        """
        deadline = time.time() + max(0.0, timeout)
        while True:
            if self.capture_count(coll, batch) == 0:
                return True
            if time.time() >= deadline:
                return False
            time.sleep(poll)

    # ===== helpers for the recorder process =================================
    @staticmethod
    def parse_batch_archive_path(path):
        """Parse a batch archive dir key of the form
        ``<...>/<coll>/batches/<batch>/archive``.

        Returns ``(coll, batch)`` or None.
        """
        if not path:
            return None
        parts = os.path.normpath(path).split(os.sep)
        for i, part in enumerate(parts):
            if (part == BatchManager.BATCHES_DIRNAME and i >= 1 and
                    i + 2 < len(parts) and
                    parts[i + 2] == BatchManager.BATCH_ARCHIVE_DIRNAME):
                return parts[i - 1], parts[i + 1]
        return None

    # ===== publish ==========================================================
    STAGING_INDEX_FILE = 'batch.cdxj'

    def _build_staging_index(self, source_dir, rel_root, staging_path):
        from pywb.indexer.cdxindexer import write_multi_cdx_index

        if os.path.isfile(staging_path):
            os.remove(staging_path)

        write_multi_cdx_index(
            staging_path, [source_dir],
            append_post=True, cdxj=True, sort=True,
            recurse=True, rel_root=os.path.abspath(rel_root))

        with open(staging_path, 'rb') as fh:
            return [ln for ln in
                    (raw.rstrip(b'\n') for raw in fh) if ln]

    @staticmethod
    def _validate_payload_refs(lines, archive_root):
        """Ensure every CDX payload reference exists and its record range
        (offset..offset+length) is readable. Opens each referenced WARC once.
        """
        from pywb.warcserver.index.cdxobject import CDXObject, OFFSET, LENGTH, \
            FILENAME

        handles = {}
        try:
            for line in lines:
                cdx = CDXObject(cdxline=line)
                rel_name = cdx[FILENAME].replace('/', os.sep)
                full_path = os.path.normpath(
                    os.path.join(archive_root, rel_name))

                fh = handles.get(full_path)
                if fh is None:
                    if not os.path.isfile(full_path):
                        raise BatchError(
                            'Batch payload reference is missing: ' +
                            full_path)
                    try:
                        fh = open(full_path, 'rb')
                    except OSError as exc:
                        raise BatchError(
                            'Batch payload reference is not readable: '
                            '{0}: {1}'.format(full_path, exc))
                    handles[full_path] = fh

                try:
                    offset = int(cdx[OFFSET])
                    length = int(cdx[LENGTH])
                    if length > 0:
                        fh.seek(offset + length - 1)
                        if not fh.read(1):
                            raise BatchError(
                                'Batch payload reference is truncated: ' +
                                full_path)
                    else:
                        fh.seek(offset)
                except (ValueError, OSError) as exc:
                    raise BatchError(
                        'Batch payload reference is not readable: '
                        '{0}: {1}'.format(full_path, exc))
        finally:
            for fh in handles.values():
                fh.close()

    @staticmethod
    def _rewrite_filenames(lines, public_prefix):
        from pywb.warcserver.index.cdxobject import CDXObject, FILENAME

        result = []
        for line in lines:
            cdx = CDXObject(cdxline=line)
            cdx[FILENAME] = public_prefix + '/' + cdx[FILENAME]
            result.append(cdx.to_cdxj().rstrip('\n'))
        return result

    def _atomic_write_text(self, dest_path, text, makedirs_=False):
        dest_dir = os.path.dirname(dest_path)
        if makedirs_ and not os.path.isdir(dest_dir):
            os.makedirs(dest_dir)

        fd, tmp = tempfile.mkstemp(
            dir=dest_dir,
            prefix='.' + os.path.basename(dest_path) + '.',
            suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
            os.replace(tmp, dest_path)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def publish_batch(self, coll, batch, wait=30.0, poll=0.1):
        """Publish a sealed batch atomically.

        Returns True if the batch was (just) published, False if it was
        already published (idempotent no-op). Raises BatchError and leaves
        the batch in ``sealed`` state on any failure (safe to retry).
        """
        self._validate_batch_name(batch)

        state = self.get_state(coll, batch)
        if state == STATE_PUBLISHED:
            return False
        self._require_state(coll, batch, STATE_SEALED)

        if not self.wait_drained(coll, batch, wait, poll):
            raise BatchError(
                'Batch {0} still has accepted captures in flight, '
                'try again later'.format(batch))

        batch_archive = self.batch_archive_dir(coll, batch)
        batch_indexes = self.batch_indexes_dir(coll, batch)
        public_archive_root = os.path.join(self._coll_dir(coll),
                                            self.BATCH_ARCHIVE_DIRNAME)
        pub_archive = self.pub_batch_archive_dir(coll, batch)
        pub_index = self.pub_batch_index_file(coll, batch)
        staging = os.path.join(batch_indexes, self.STAGING_INDEX_FILE)

        # reconcile an interrupted previous attempt
        migrated = os.path.isdir(pub_archive)
        if migrated and os.path.isdir(batch_archive):
            raise BatchError(
                'Batch {0} has both staging and public payload directories, '
                'manual intervention required'.format(batch))
        if not migrated and not os.path.isdir(batch_archive):
            raise BatchError(
                'Batch payload directory is missing: ' + batch_archive)
        if not migrated and os.path.exists(pub_index):
            raise BatchError(
                'Published index exists without payload directory: ' +
                pub_index)

        if migrated:
            # previous attempt moved the payloads; index them in place
            lines = self._build_staging_index(
                pub_archive, public_archive_root, staging)
            self._validate_payload_refs(lines, public_archive_root)
            final_lines = [CDXObject_to_text(line) for line in lines]
        else:
            # validate everything BEFORE touching the public directories
            lines = self._build_staging_index(
                batch_archive, batch_archive, staging)
            self._validate_payload_refs(lines, batch_archive)
            final_lines = self._rewrite_filenames(
                lines, self.PUB_BATCHES_DIRNAME + '/' + batch)

        text = '\n'.join(final_lines)
        if final_lines:
            text += '\n'

        if not migrated:
            # 1) payloads become public as one atomic directory rename ...
            def move_payloads():
                if not os.path.isdir(os.path.dirname(pub_archive)):
                    os.makedirs(os.path.dirname(pub_archive))
                os.replace(batch_archive, pub_archive)

            self._wait_for_fs_op(move_payloads, timeout=wait, poll=poll)

        # 2) ... followed by the single, complete index file becoming visible
        self._atomic_write_text(pub_index, text, makedirs_=True)

        warcs = sorted({line_filename(line) for line in lines})

        data = self._read_state(coll, batch)
        data['state'] = STATE_PUBLISHED
        data['published_at'] = self._utc_now()
        data['archive_dir'] = os.path.join(
            self.BATCH_ARCHIVE_DIRNAME, self.PUB_BATCHES_DIRNAME, batch)
        data['index_file'] = os.path.join(
            self.BATCH_INDEXES_DIRNAME,
            self.BATCH_INDEX_PREFIX + batch + self.BATCH_INDEX_SUFFIX)
        data['warcs'] = warcs
        self._write_state(coll, batch, data)

        # tidy staging residue (the batch is closed for writing now)
        for path in (staging,
                     self.pending_file(coll, batch),
                     self.pending_file(coll, batch) + '.lock'):
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass

        return True

    # ===== discard =========================================================
    def discard_batch(self, coll, batch, wait=30.0, poll=0.1):
        """Discard a sealed batch: delete all payloads and staging indexes,
        leaving only a discarded tombstone. Returns False if already
        discarded (idempotent).
        """
        self._validate_batch_name(batch)

        state = self.get_state(coll, batch)
        if state == STATE_DISCARDED:
            return False
        self._require_state(coll, batch, STATE_SEALED)

        if not self.wait_drained(coll, batch, wait, poll):
            raise BatchError(
                'Batch {0} still has accepted captures in flight, '
                'try again later'.format(batch))

        # the batch never entered public archive/index dirs; remove all
        # externally referenceable payload files
        def remove_payloads():
            for path in (self.batch_archive_dir(coll, batch),
                         self.batch_indexes_dir(coll, batch)):
                if os.path.isdir(path):
                    shutil.rmtree(path)
            for path in (self.pending_file(coll, batch),
                         self.pending_file(coll, batch) + '.lock'):
                if os.path.isfile(path):
                    os.remove(path)

        self._wait_for_fs_op(remove_payloads, timeout=wait, poll=poll)

        tombstone = self._read_state(coll, batch) or {
            'batch': batch, 'collection': coll}
        tombstone['state'] = STATE_DISCARDED
        tombstone['discarded_at'] = self._utc_now()
        self._write_state(coll, batch, tombstone)

        return True

    # ===== filesystem retry ================================================
    @staticmethod
    def _wait_for_fs_op(op, timeout=30.0, poll=0.1):
        """Retry a filesystem move/delete while Windows may hold handles."""
        deadline = time.time() + max(0.0, timeout)
        while True:
            try:
                return op()
            except OSError:
                if time.time() >= deadline:
                    raise
                time.sleep(poll)


# ============================================================================
def CDXObject_to_text(line):
    """Serialize a raw CDXJ line back to its canonical single-line text."""
    from pywb.warcserver.index.cdxobject import CDXObject
    return CDXObject(cdxline=line).to_cdxj().rstrip('\n')


def line_filename(line):
    from pywb.warcserver.index.cdxobject import CDXObject, FILENAME
    return CDXObject(cdxline=line)[FILENAME]
