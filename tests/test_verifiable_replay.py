import base64
import hashlib
import os
from io import BytesIO
from six.moves.urllib.parse import urlsplit

from warcio import WARCWriter, StatusAndHeaders

from pywb.manager.manager import main as wb_manager
from pywb.warcserver.index.cdxobject import CDXObject

from .base_config_test import BaseConfigTest, CollsDirMixin


def sha1_b32(payload):
    return base64.b32encode(hashlib.sha1(payload).digest()).decode().rstrip('=')


def http_headers(status, headers):
    return StatusAndHeaders(status, headers, protocol='HTTP/1.0')


# ============================================================================
class TestVerifiableReplay(CollsDirMixin, BaseConfigTest):
    @classmethod
    def setup_class(cls):
        super(TestVerifiableReplay, cls).setup_class(
            'config_test.yaml',
            custom_config={'verifiable_replay_secret': 'test-vrr-secret'})
        cls._write_colls()

    @staticmethod
    def _ref_path(res):
        """Vr-Ref is an absolute url; return the request path portion."""
        path = urlsplit(res.headers['Vr-Ref']).path
        assert path.startswith('/')
        return path

    # ----- fixtures --------------------------------------------------------
    @classmethod
    def _write_colls(cls):
        # main collection
        # two different entities at the same url and second-level timestamp
        cls.alpha = b'ALPHA-ENTITY-111'
        cls.beta = b'BETA-ENTITY-2222'
        cls.donor_payload = b'DONOR-PAYLOAD-xyz'
        cls.redir_payload = b'some\ntext'

        filename = os.path.join(cls.root_dir, 'vrtest.warc.gz')
        with open(filename, 'wb') as fh:
            cls.writer = WARCWriter(fh, gzip=True)
            cls.writer.write_record(cls._response_cls(
                'http://example.com/page', '2020-01-01T00:00:00Z',
                '200 OK', cls.alpha))
            cls.writer.write_record(cls._response_cls(
                'http://example.com/page', '2020-01-01T00:00:00Z',
                '200 OK', cls.beta))
            cls.writer.write_record(cls._response_cls(
                'http://example.com/donor', '2020-01-01T00:00:00Z',
                '200 OK', cls.donor_payload))
            cls.writer.write_record(cls._revisit_cls(
                'http://example.com/revisit', '2022-01-01T00:00:00Z',
                '200 OK', sha1_b32(cls.donor_payload),
                'http://example.com/donor', '2020-01-01T00:00:00Z',
                content_length=len(cls.donor_payload)))
            cls.writer.write_record(cls._response_cls(
                'http://example.com/redir-orig', '2020-01-01T00:00:00Z',
                '301 Permanent Redirect', cls.redir_payload,
                location='https://example.com/dest'))
            cls.writer.write_record(cls._revisit_cls(
                'http://example.com/go', '2022-01-01T00:00:00Z',
                '301 Permanent Redirect', sha1_b32(cls.redir_payload),
                'http://example.com/redir-orig', '2020-01-01T00:00:00Z',
                location='https://example.com/dest'))

        wb_manager(['init', 'vrtest'])
        wb_manager(['add', 'vrtest', filename])

        # a plain (uncompressed) warc in its own collection for byte-level
        # failure injection
        cls.mut_payload = b'FINGERPRINT-MUTABLE-PAYLOAD'
        plain = os.path.join(cls.root_dir, 'vrtamper.warc')
        with open(plain, 'wb') as fh:
            writer = WARCWriter(fh, gzip=False)
            writer.write_record(cls._response_cls(
                'http://example.com/tamper', '2020-01-01T00:00:00Z',
                '200 OK', cls.mut_payload, writer=writer))

        wb_manager(['init', 'vrtamper'])
        wb_manager(['add', 'vrtamper', plain])
        cls.plain_warc = plain

        # an unrelated second collection
        other = os.path.join(cls.root_dir, 'vrother.warc.gz')
        with open(other, 'wb') as fh:
            writer = WARCWriter(fh, gzip=True)
            writer.write_record(cls._response_cls(
                'http://other.example/', '2020-01-01T00:00:00Z',
                '200 OK', b'OTHER-COLLECTION', writer=writer))

        wb_manager(['init', 'vrother'])
        wb_manager(['add', 'vrother', other])

    @staticmethod
    def _http_headers(status, headers):
        return StatusAndHeaders(status, headers, protocol='HTTP/1.0')

    @classmethod
    def _response_cls(cls, url, date, status, payload, location=None,
                      extra_headers=None, writer=None):
        headers = [('Content-Type', 'text/plain; charset="UTF-8"'),
                   ('Content-Length', str(len(payload)))]
        if location:
            headers.append(('Location', location))
        if extra_headers:
            headers.extend(extra_headers)
        writer = writer or cls.writer
        return writer.create_warc_record(
            url,
            record_type='response',
            http_headers=cls._http_headers(status, headers),
            payload=BytesIO(payload),
            warc_headers_dict={'WARC-Date': date},
            length=len(payload))

    @classmethod
    def _revisit_cls(cls, url, date, status, digest, refers_uri, refers_date,
                     location=None, content_length=0, writer=None):
        headers = [('Content-Type', 'text/plain; charset="UTF-8"'),
                   ('Content-Length', str(content_length))]
        if location:
            headers.append(('Location', location))
        writer = writer or cls.writer
        return writer.create_revisit_record(
            url,
            digest='sha1:' + digest,
            refers_to_uri=refers_uri,
            refers_to_date=refers_date,
            warc_headers_dict={'WARC-Date': date},
            http_headers=cls._http_headers(status, headers))

    # ----- helpers ---------------------------------------------------------
    def _rows(self, coll, url):
        path = os.path.join(self.root_dir, self.COLLS_DIR, coll,
                            'indexes', 'index.cdxj')
        rows = []
        with open(path, 'rb') as fh:
            for line in fh:
                cdx = CDXObject(line.rstrip())
                if cdx.get('url') == url and cdx.get('filename') != '-':
                    rows.append(cdx)
        return rows

    def _mint(self, coll, cdx, rec_type='response',
              payload_cdx=None, payload_url=None, payload_ts=None):
        payload_cdx = payload_cdx or cdx
        return self.app_non_frame.warcserver.vr_codec.mint(
            coll=coll,
            url=cdx['url'],
            timestamp=cdx['timestamp'],
            digest=cdx.get('digest', ''),
            rec_type=rec_type,
            header_loc=(cdx['filename'], cdx['offset'], cdx.get('length', '-')),
            payload_loc=(payload_cdx['filename'], payload_cdx['offset'],
                         payload_cdx.get('length', '-')),
            payload_url=payload_url or payload_cdx['url'],
            payload_ts=payload_ts or payload_cdx['timestamp'])

    def _vr_path(self, coll, token):
        return '/{0}/vr_/urn:vr:{1}'.format(coll, token)

    # ----- ordinary behaviour stays unchanged ------------------------------
    def test_ordinary_timestamp_replay_unchanged(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20200101000000/http://example.com/page', status=200)
        # closest replay keeps its own (index order based) choice
        assert res.body in (self.alpha, self.beta)

    def test_latest_replay_unchanged(self):
        res = self.testapp_non_frame.get(
            '/vrtest/http://example.com/page', status=200)
        assert res.body in (self.alpha, self.beta)

    # ----- minting ----------------------------------------------------------
    def test_normal_response_mints_reference(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20200101000000/http://example.com/page', status=200)
        ref = self._ref_path(res)
        assert ref.startswith('/vrtest/vr_/urn:vr:vr1.')

        claims = self.app_non_frame.warcserver.vr_codec.decode(
            ref.split('urn:vr:', 1)[1])
        assert claims['coll'] == 'vrtest'
        assert claims['url'] == 'http://example.com/page'
        assert claims['ts'] == '20200101000000'
        assert claims['rec_type'] == 'response'
        assert claims['p'] == claims['h']

    def test_framed_inner_replay_mints_reference(self):
        res = self.testapp.get(
            '/vrtest/20200101000000mp_/http://example.com/page', status=200)
        assert self._ref_path(res).startswith('/vrtest/vr_/urn:vr:vr1.')

    def test_framed_inner_pinned_replay(self):
        res = self.testapp.get(
            '/vrtest/20200101000000mp_/http://example.com/page', status=200)
        again = self.testapp.get(self._ref_path(res), status=200)
        assert again.body == res.body

    # ----- pinned replay ----------------------------------------------------
    def test_reference_replays_same_record(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20200101000000/http://example.com/page', status=200)
        vr_path = self._ref_path(res)

        again = self.testapp_non_frame.get(vr_path, status=200)
        assert again.body == res.body
        # same token is echoed, no new binding is produced
        assert self._ref_path(again) == vr_path
        # same-resource identification keeps the binding
        assert 'vr_/urn:vr:' in again.headers['Content-Location']

    def test_same_second_entities_never_switch(self):
        rows = self._rows('vrtest', 'http://example.com/page')
        assert len(rows) == 2
        cdx_a, cdx_b = rows

        token_a = self._mint('vrtest', cdx_a)
        token_b = self._mint('vrtest', cdx_b)

        body_a = self.testapp_non_frame.get(self._vr_path('vrtest', token_a),
                                            status=200).body
        body_b = self.testapp_non_frame.get(self._vr_path('vrtest', token_b),
                                            status=200).body
        body_b_again = self.testapp_non_frame.get(
            self._vr_path('vrtest', token_b), status=200).body

        assert body_a != body_b
        assert {body_a, body_b} == {self.alpha, self.beta}
        # repeated use with added candidates / reordered results is stable
        assert body_b == body_b_again

        # ordinary timestamp replay keeps its own behaviour, while the
        # reference of the capture it actually selected stays bound to it
        ordinary = self.testapp_non_frame.get(
            '/vrtest/20200101000000/http://example.com/page', status=200)
        assert ordinary.body in (self.alpha, self.beta)
        ordinary_vr = self.testapp_non_frame.get(self._ref_path(ordinary),
                                                 status=200)
        assert ordinary_vr.body == ordinary.body

    def test_revisit_reference_pins_donor(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20220101000000/http://example.com/revisit', status=200)
        assert res.body == self.donor_payload

        vr_path = self._ref_path(res)
        token = vr_path.split('urn:vr:', 1)[1]
        claims = self.app_non_frame.warcserver.vr_codec.decode(token)
        assert claims['rec_type'] == 'revisit'
        assert claims['url'] == 'http://example.com/revisit'
        assert claims['p_url'] == 'http://example.com/donor'
        assert claims['p_ts'] == '20200101000000'
        assert claims['p'] != claims['h']
        assert claims['digest'] == sha1_b32(self.donor_payload)

        again = self.testapp_non_frame.get(vr_path, status=200)
        assert again.body == self.donor_payload

    def test_redirect_revisit_keeps_binding_but_not_snapshot(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20220101000000/http://example.com/go', status=301)
        assert res.body == b''
        assert res.headers['Location'].endswith(
            '/20220101000000/https://example.com/dest')
        assert 'vr_' not in res.headers['Location']

        vr_path = self._ref_path(res)
        again = self.testapp_non_frame.get(vr_path, status=301)
        assert again.body == b''
        # the redirect target is a *different* resource and stays on normal
        # url/timestamp replay -- this is no full-page snapshot
        assert again.headers['Location'].endswith(
            '/20220101000000/https://example.com/dest')
        assert 'vr_' not in again.headers['Location']

    # ----- failure handling -------------------------------------------------
    def test_malformed_reference_is_400(self):
        self.testapp_non_frame.get(
            '/vrtest/vr_/urn:vr:not-a-reference', status=400)

    def test_tampered_signature_is_400(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20200101000000/http://example.com/page', status=200)
        token = self._ref_path(res).split('urn:vr:', 1)[1]
        bad = token[:-2] + 'AA'
        self.testapp_non_frame.get(self._vr_path('vrtest', bad), status=400)

    def test_cross_collection_rejected(self):
        res = self.testapp_non_frame.get(
            '/vrtest/20200101000000/http://example.com/page', status=200)
        token = self._ref_path(res).split('urn:vr:', 1)[1]
        # the same token presented to another collection is refused
        self.testapp_non_frame.get(self._vr_path('vrother', token), status=400)

    def _tamper_archive_path(self):
        # manager imports the warc into the collection's archive directory
        return os.path.join(self.root_dir, self.COLLS_DIR, 'vrtamper',
                            'archive', 'vrtamper.warc')

    def test_missing_record_reports_unavailable(self):
        res = self.testapp_non_frame.get(
            '/vrtamper/20200101000000/http://example.com/tamper', status=200)
        vr_path = self._ref_path(res)

        archive = self._tamper_archive_path()
        assert os.path.isfile(archive)
        os.remove(archive)
        try:
            res = self.testapp_non_frame.get(vr_path, status=410)
            assert 'unavailable' in res.text.lower()
        finally:
            # restore for other tests
            with open(archive, 'wb') as fh:
                with open(self.plain_warc, 'rb') as src:
                    fh.write(src.read())

    def test_changed_payload_fingerprint_reports_unavailable(self):
        res = self.testapp_non_frame.get(
            '/vrtamper/20200101000000/http://example.com/tamper', status=200)
        vr_path = self._ref_path(res)

        archive = self._tamper_archive_path()
        with open(archive, 'rb') as fh:
            data = fh.read()
        index = data.find(b'FINGERPRINT')
        assert index > 0
        mutated = data[:index] + b'X' + data[index + 1:]
        assert len(mutated) == len(data)
        try:
            with open(archive, 'wb') as fh:
                fh.write(mutated)

            res = self.testapp_non_frame.get(vr_path, status=410)
            assert 'fingerprint' in res.text.lower()
            assert 'unavailable' in res.text.lower()
        finally:
            with open(archive, 'wb') as fh:
                fh.write(data)


# ============================================================================
class TestVerifiableReplayAccess(BaseConfigTest):
    """Pinned replay stays subject to the collection's current access rules"""

    @classmethod
    def setup_class(cls):
        super(TestVerifiableReplayAccess, cls).setup_class(
            'config_test_access.yaml',
            custom_config={'verifiable_replay_secret': 'test-vrr-secret'})

    def test_blocked_pinned_replay(self):
        # a reference to a capture that is blocked under the current rules,
        # minted out of band (as it would have been before the block)
        token = self.app_non_frame.warcserver.vr_codec.mint(
            coll='pywb',
            url='http://www.iana.org/about',
            timestamp='20140126200706',
            digest='6G77LZKFAVKH4PCWWKMW6TRJPSHWUBI3',
            rec_type='response',
            header_loc=('iana.warc.gz', '483588', '2962'),
            payload_loc=('iana.warc.gz', '483588', '2962'),
            payload_url='http://www.iana.org/about',
            payload_ts='20140126200706')

        self.testapp_non_frame.get(
            '/pywb/vr_/urn:vr:' + token, status=451)

    def test_allowed_pinned_replay(self):
        token = self.app_non_frame.warcserver.vr_codec.mint(
            coll='pywb',
            url='http://www.iana.org/',
            timestamp='20140126200624',
            digest='OSSAPWJ23L56IYVRW3GFEAR4MCJMGPTB',
            rec_type='response',
            header_loc=('iana.warc.gz', '334', '2258'),
            payload_loc=('iana.warc.gz', '334', '2258'),
            payload_url='http://www.iana.org/',
            payload_ts='20140126200624')

        # an allowed capture replays normally through the reference
        self.testapp_non_frame.get(
            '/pywb/vr_/urn:vr:' + token, status=200)
