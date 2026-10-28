from gevent import monkey; monkey.patch_all()

import base64
import hashlib
from io import BytesIO
import json
import os

import pytest
import webtest
from warcio import WARCWriter, StatusAndHeaders
from warcio.recordloader import ArcWarcRecordLoader
from warcio.statusandheaders import StatusAndHeadersParser

from pywb.utils.canonicalize import canonicalize
from pywb.utils.wbexception import AccessException
from pywb.warcserver.access_checker import AccessChecker, FileAccessIndexSource
from pywb.warcserver.basewarcserver import BaseWarcServer
from pywb.warcserver.handlers import DefaultResourceHandler
from pywb.warcserver.index.aggregator import SimpleAggregator, DirectoryIndexSource
from pywb.warcserver.test.testutils import BaseTestClass, TempDirTests, TEST_CDX_PATH, TEST_WARC_PATH
from pywb.warcserver.vrref import VRReferenceCodec, parse_claims


def payload_digest(payload):
    return base64.b32encode(hashlib.sha1(payload).digest()).decode().rstrip('=')


def cdxj_json(**fields):
    return json.dumps(fields, sort_keys=True)


# ============================================================================
class TestVRReferenceCodec(object):
    def setup_method(self):
        self.codec = VRReferenceCodec('a-shared-secret')

    def test_mint_decode_roundtrip(self):
        token = self.codec.mint(
            coll='pywb', url='http://example.com/', timestamp='20140127171200',
            digest='B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A', rec_type='response',
            header_loc=('a.warc.gz', '334', '1046'),
            payload_loc=('a.warc.gz', '334', '1046'),
            payload_url='http://example.com/', payload_ts='20140127171200')

        assert token.startswith('vr1.')
        claims = self.codec.decode(token)
        assert claims['coll'] == 'pywb'
        assert claims['ts'] == '20140127171200'
        assert claims['url'] == 'http://example.com/'
        assert claims['digest'] == 'B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
        assert claims['h'] == ('a.warc.gz', '334', '1046')
        assert claims['p'] == ('a.warc.gz', '334', '1046')
        assert claims['p_url'] == 'http://example.com/'
        assert claims['p_ts'] == '20140127171200'
        assert claims['rec_type'] == 'response'

    def test_digest_prefix_normalized(self):
        token = self.codec.mint(
            coll='c', url='http://example.com/', timestamp='20140127171200',
            digest='sha1:b2ltwwpuoyah7uipq7zupq4vmbsvc36a', rec_type='response',
            header_loc=('a.warc.gz', '1', '2'),
            payload_loc=('a.warc.gz', '1', '2'),
            payload_url='http://example.com/', payload_ts='20140127171200')

        claims = self.codec.decode(token)
        assert claims['digest'] == 'sha1:B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'

    def test_tampered_signature(self):
        token = self.codec.mint(
            coll='c', url='http://example.com/', timestamp='20140127171200',
            digest='B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A', rec_type='response',
            header_loc=('a.warc.gz', '1', '2'),
            payload_loc=('a.warc.gz', '1', '2'),
            payload_url='http://example.com/', payload_ts='20140127171200')

        with pytest.raises(ValueError):
            self.codec.decode(token[:-2] + ('AA' if not token.endswith('AA') else 'BB'))

    def test_wrong_secret(self):
        token = self.codec.mint(
            coll='c', url='http://example.com/', timestamp='20140127171200',
            digest='B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A', rec_type='response',
            header_loc=('a.warc.gz', '1', '2'),
            payload_loc=('a.warc.gz', '1', '2'),
            payload_url='http://example.com/', payload_ts='20140127171200')

        with pytest.raises(ValueError):
            VRReferenceCodec('other-secret').decode(token)

    @pytest.mark.parametrize('bad', [None, '', 'foo', 'vr1.', 'vr2.a.b',
                                     'vr1.###.bbb'])
    def test_malformed(self, bad):
        with pytest.raises(ValueError):
            parse_claims(bad if bad else 'x')

    def test_unsigned_claims_need_no_secret(self):
        token = self.codec.mint(
            coll='c', url='http://example.com/', timestamp='20140127171200',
            digest='B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A', rec_type='revisit',
            header_loc=('h.warc.gz', '1', '2'),
            payload_loc=('p.warc.gz', '3', '4'),
            payload_url='http://example.net/', payload_ts='20140127171100')

        claims = parse_claims(token)
        assert claims['coll'] == 'c'
        assert claims['p'] == ('p.warc.gz', '3', '4')
        assert claims['p_url'] == 'http://example.net/'


# ============================================================================
def _resign(codec, claims, **overrides):
    """Re-sign (valid HMAC) claims with mutated fields, simulating an index
    that changed after the token was minted."""
    values = dict(coll=claims['coll'], url=claims['url'],
                  timestamp=claims['ts'], digest=claims['digest'],
                  rec_type=claims['rec_type'],
                  header_loc=claims['h'], payload_loc=claims['p'],
                  payload_url=claims['p_url'], payload_ts=claims['p_ts'])
    values.update(overrides)
    return codec.mint(**values)


class TestPinnedReplay(TempDirTests, BaseTestClass):
    @classmethod
    def setup_class(cls):
        super(TestPinnedReplay, cls).setup_class()

        cls.codec = VRReferenceCodec('pinned-secret')

        source = SimpleAggregator({'local': DirectoryIndexSource(TEST_CDX_PATH)})

        # a collection with an access rule that blocks the example.com
        # capture
        aclj = os.path.join(cls.root_dir, 'blocks.aclj')
        with open(aclj, 'wb') as fh:
            fh.write(b'com,example)/ 20140127171200 {"access": "block"}\n')
        access = AccessChecker(
            SimpleAggregator({'acl': FileAccessIndexSource(aclj)}))

        app = BaseWarcServer()
        app.add_route('/vr',
                      DefaultResourceHandler(source, TEST_WARC_PATH,
                                             vr_codec=cls.codec))

        source2 = SimpleAggregator({'local': DirectoryIndexSource(TEST_CDX_PATH)})
        app.add_route('/other',
                      DefaultResourceHandler(source2, TEST_WARC_PATH,
                                             vr_codec=cls.codec))

        source3 = SimpleAggregator({'local': DirectoryIndexSource(TEST_CDX_PATH)})
        app.add_route('/vra',
                      DefaultResourceHandler(source3, TEST_WARC_PATH,
                                             vr_codec=cls.codec,
                                             access_checker=access))

        # a collection with two different entities at the exact same url and
        # second-level timestamp
        cls.dup_url = 'http://dup.example/'
        cls.dup_ts = '20200301000000'
        cls.dup_payloads = [b'DUP-ONE-CONTENT', b'DUP-TWO-CONTENT']

        index_dir = os.path.join(cls.root_dir, 'dup-index')
        archive_dir = os.path.join(cls.root_dir, 'dup-archive')
        os.makedirs(index_dir)
        os.makedirs(archive_dir)

        warc_path = os.path.join(archive_dir, 'dupes2.warc')
        rows = []
        with open(warc_path, 'wb') as fh:
            writer = WARCWriter(fh, gzip=False)
            for payload in cls.dup_payloads:
                record = writer.create_warc_record(
                    cls.dup_url, 'response',
                    http_headers=StatusAndHeaders(
                        '200 OK',
                        [('Content-Type', 'text/plain'),
                         ('Content-Length', str(len(payload)))],
                        protocol='HTTP/1.0'),
                    payload=BytesIO(payload),
                    warc_headers_dict={'WARC-Date': '2020-03-01T00:00:00Z'},
                    length=len(payload))
                offset = fh.tell()
                writer.write_record(record)
                length = fh.tell() - offset
                rows.append((offset, length, payload_digest(payload)))

        cdxj_path = os.path.join(index_dir, 'dupes2.cdxj')
        with open(cdxj_path, 'w') as fh:
            for offset, length, digest in rows:
                fields = cdxj_json(url=cls.dup_url, mime='text/plain',
                                   status='200', digest=digest,
                                   length=str(length), offset=str(offset),
                                   filename='dupes2.warc')
                fh.write('{0} {1} {2}\n'.format(canonicalize(cls.dup_url),
                                                cls.dup_ts, fields))

        dup_source = SimpleAggregator(
            {'local': DirectoryIndexSource(index_dir)})
        app.add_route('/vd',
                      DefaultResourceHandler(dup_source,
                                             os.path.join(archive_dir, ''),
                                             vr_codec=cls.codec))

        cls.testapp = webtest.TestApp(app)
        cls.dup_rows = rows

    # ------------------------------------------------------------------
    def _get_ref(self, route, url, closest):
        resp = self.testapp.get('{0}/resource?url={1}&closest={2}'.format(
            route, url, closest))
        token = resp.headers.get('Warcserver-Vr-Ref')
        assert token, 'a verifiable replay reference must be minted'
        return token, resp

    def _replay_ref(self, route, token, **kwargs):
        return self.testapp.get('{0}/resource?vrref={1}'.format(route, token),
                                **kwargs)

    @staticmethod
    def _parse(resp):
        return ArcWarcRecordLoader().parse_record_stream(BytesIO(resp.body),
                                                         ensure_http_headers=True)

    # ------------------------------------------------------------------
    def test_response_mint_and_pinned_replay(self):
        token, resp = self._get_ref('/vr', 'http://example.com',
                                   '20140127171200')

        claims = self.codec.decode(token)
        assert claims['coll'] == 'vr'
        assert claims['url'] == 'http://example.com'
        assert claims['ts'] == '20140127171200'
        assert claims['digest'] == 'B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
        assert claims['h'] == ('dupes.warc.gz', '334', '1046')
        assert claims['p'] == claims['h']
        assert claims['rec_type'] == 'response'

        pinned = self._replay_ref('/vr', token)
        assert pinned.status_int == 200

        orig = self._parse(resp)
        again = self._parse(pinned)
        assert again.rec_headers.get_header('WARC-Target-URI') == 'http://example.com'
        assert again.rec_headers.get_header('WARC-Date') == '2014-01-27T17:12:00Z'
        assert again.content_stream().read() == orig.content_stream().read()
        assert b'<!doctype html>' in pinned.body

        # the replay echoes the same reference, it does not mint a new one
        assert pinned.headers.get('Warcserver-Vr-Ref') == token

    def test_revisit_pins_donor(self):
        token, resp = self._get_ref('/vr', 'http://example.com',
                                   '20140127171251')

        claims = self.codec.decode(token)
        assert claims['rec_type'] == 'revisit'
        # the donor payload is a different record
        assert claims['h'] == ('dupes.warc.gz', '11875', '553')
        assert claims['p'] == ('dupes.warc.gz', '334', '1046')
        assert claims['p_url'] == 'http://example.com'
        assert claims['p_ts'] == '20140127171200'

        pinned = self._replay_ref('/vr', token)
        record = self._parse(pinned)
        assert record.rec_headers.get_header('WARC-Target-URI') == 'http://example.com'
        assert record.rec_headers.get_header('WARC-Date') == '2014-01-27T17:12:51Z'
        assert (record.rec_headers.get_header('WARC-Refers-To-Target-URI') ==
                'http://example.com')
        assert b'<!doctype html>' in pinned.body

    def test_same_second_entities_do_not_switch(self):
        # ordinary closest replay selects a single candidate (first row)
        default_resp = self.testapp.get(
            '/vd/resource?url={0}&closest={1}'.format(self.dup_url, self.dup_ts))
        default_body = self._parse(default_resp).content_stream().read()
        assert default_body in self.dup_payloads

        token_one, _ = self._get_ref('/vd', self.dup_url, self.dup_ts)
        claims_one = self.codec.decode(token_one)

        # mint a reference for the OTHER same-second entity directly from
        # its index row (as an additional index source/order change would
        # surface)
        rows = self.dup_rows
        other_index = 1 if claims_one['h'][1] == str(rows[0][0]) else 0
        offset, length, digest = rows[other_index]
        token_two = self.codec.mint(
            coll='vd', url=self.dup_url, timestamp=self.dup_ts,
            digest=digest, rec_type='response',
            header_loc=('dupes2.warc', str(offset), str(length)),
            payload_loc=('dupes2.warc', str(offset), str(length)),
            payload_url=self.dup_url, payload_ts=self.dup_ts)

        body_one = self._parse(self._replay_ref('/vd', token_one)).content_stream().read()
        body_two = self._parse(self._replay_ref('/vd', token_two)).content_stream().read()

        # closest replay is unchanged, but each reference always replays the
        # record it was minted for -- they never switch
        assert body_one == default_body
        assert {body_one, body_two} == set(self.dup_payloads)
        assert body_one != body_two

        # replay repeatedly: a second lookup must return the same record too
        assert (self._parse(self._replay_ref('/vd', token_two)).content_stream().read()
                == body_two)

    def test_bad_signature_is_400(self):
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171200')
        bad = token[:-2] + ('00' if not token.endswith('00') else '11')
        resp = self._replay_ref('/vr', bad, status=400)
        assert 'Invalid verifiable replay reference' in resp.json['message']

    def test_garbage_token_is_400(self):
        resp = self._replay_ref('/vr', 'not-a-reference', status=400)
        assert 'Invalid verifiable replay reference' in resp.json['message']

    def test_changed_offset_reports_unavailable(self):
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171200')
        claims = self.codec.decode(token)
        mutated = _resign(self.codec, claims,
                          header_loc=('dupes.warc.gz', '999999', '1046'),
                          payload_loc=('dupes.warc.gz', '999999', '1046'))
        resp = self._replay_ref('/vr', mutated, status=410)
        assert 'no longer matches' in resp.json['message']

    def test_changed_digest_reports_unavailable(self):
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171200')
        claims = self.codec.decode(token)
        mutated = _resign(self.codec, claims,
                          digest='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        resp = self._replay_ref('/vr', mutated, status=410)
        assert 'digest changed' in resp.json['message']

    def test_arbitrary_filename_rejected(self):
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171200')
        claims = self.codec.decode(token)
        mutated = _resign(self.codec, claims,
                          header_loc=('../../../../etc/passwd', '0', '10'),
                          payload_loc=('../../../../etc/passwd', '0', '10'))
        # the locator must match a current index row first, so the arbitrary
        # path is never opened
        resp = self._replay_ref('/vr', mutated, status=410)
        assert 'no longer matches' in resp.json['message']

    def test_missing_donor_reports_unavailable(self):
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171251')
        claims = self.codec.decode(token)
        mutated = _resign(self.codec, claims,
                          payload_loc=('dupes.warc.gz', '999999', '1046'))
        resp = self._replay_ref('/vr', mutated, status=410)
        assert 'donor record' in resp.json['message']
        assert 'no longer matches' in resp.json['message']

    def test_cross_collection_rejected(self):
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171200')
        resp = self._replay_ref('/other', token, status=410)
        assert 'can not be replayed' in resp.json['message']

    def test_current_access_rules_still_control_pinned_replay(self):
        # token minted (out of band) for the access controlled collection
        token = self.codec.mint(
            coll='vra', url='http://example.com', timestamp='20140127171200',
            digest='B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A', rec_type='response',
            header_loc=('dupes.warc.gz', '334', '1046'),
            payload_loc=('dupes.warc.gz', '334', '1046'),
            payload_url='http://example.com', payload_ts='20140127171200')

        # the pinned replay is blocked by the collection's current rules
        resp = self._replay_ref('/vra', token, status=451)
        assert resp.json['access'] == 'block'

    def test_live_web_is_not_used_as_fallback(self):
        # a reference into the future has no matching index row and must not
        # fall through to the live web loader
        token, _ = self._get_ref('/vr', 'http://example.com', '20140127171200')
        claims = self.codec.decode(token)
        mutated = _resign(self.codec, claims, timestamp='20990101000000')
        # need a valid signed token but header row can not exist at the ts
        resp = self._replay_ref('/vr', mutated, status=410)
        assert 'header record' in resp.json['message']
