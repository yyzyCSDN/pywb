from gevent import monkey; monkey.patch_all()
import gevent

from pywb.warcserver.test.testutils import TempDirTests, LiveServerTests, BaseTestClass, to_path
from pywb.warcserver.test.testutils import FakeRedisTests, HttpBinLiveTests

import os
import webtest
import pytest
from mock import patch, Mock

from fakeredis import FakeStrictRedis

from pywb.recorder.recorderapp import RecorderApp
from pywb.recorder.redisindexer import WritableRedisIndexer
from pywb.recorder.multifilewarcwriter import PerRecordWARCWriter, MultiFileWARCWriter
from pywb.recorder.filters import ExcludeSpecificHeaders, ExcludeHttpOnlyCookieHeaders
from pywb.recorder.filters import SkipDupePolicy, WriteDupePolicy, WriteRevisitDupePolicy

from pywb.utils.memento import MementoUtils

from pywb.warcserver.index.cdxobject import CDXObject

from warcio.statusandheaders import StatusAndHeadersParser
from warcio.bufferedreaders import DecompressingBufferedReader
from warcio.recordloader import ArcWarcRecordLoader
from warcio.archiveiterator import ArchiveIterator

from pywb.indexer.cdxindexer import write_cdx_index

from six.moves.urllib.parse import quote, unquote, urlencode
from io import BytesIO
import time
import json

UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'

general_req_data = "\
GET {path} HTTP/1.1\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
User-agent: %s\r\n\
X-Other: foo\r\n\
Host: {host}\r\n\
Cookie: boo=far\r\n\
\r\n" % UA



class TestRecorder(LiveServerTests, HttpBinLiveTests, FakeRedisTests, TempDirTests, BaseTestClass):
    @classmethod
    def setup_class(cls):
        super(TestRecorder, cls).setup_class()

        cls.warcs_dir = to_path(cls.root_dir + '/warcs')

        os.makedirs(cls.warcs_dir)

        cls.upstream_url = 'http://localhost:{0}'.format(cls.server.port)

    def _get_dedup_index(self, dupe_policy=WriteRevisitDupePolicy(), user=True):
        if user:
            file_key_template = '{user}:{coll}:warc'
            redis_url = 'redis://localhost/2/{user}:{coll}:cdxj'
        else:
            file_key_template = '{coll}:warc'
            redis_url = 'redis://localhost/2/{coll}:cdxj'

        dedup_index = WritableRedisIndexer(redis_url=redis_url,
                        file_key_template=file_key_template,
                        rel_path_template=to_path(self.root_dir + '/warcs/'),
                        dupe_policy=dupe_policy)

        return dedup_index

    def _test_warc_write(self, recorder_app, host, path, other_params='', link_url='', protocol='http'):
        url = protocol + '://' + host + path
        req_url = '/live/resource/postreq?url=' + url + other_params
        testapp = webtest.TestApp(recorder_app)
        resp = testapp.post(req_url, general_req_data.format(host=host, path=path).encode('utf-8'))

        if not recorder_app.write_queue.empty():
            recorder_app._write_one()

        assert resp.headers['Warcserver-Source-Coll'] == 'live'

        if not link_url:
            link_url = unquote(url)

        assert resp.headers['Link'] == MementoUtils.make_link(link_url, 'original')
        assert resp.headers['Memento-Datetime'] != ''

        return resp

    def _test_all_warcs(self, dirname, num):
        coll_dir = to_path(self.root_dir + dirname)
        assert os.path.isdir(coll_dir) == (num != None)
        if num is None:
            return

        files = [x for x in os.listdir(coll_dir) if os.path.isfile(os.path.join(coll_dir, x))]
        assert len(files) == num
        assert all(x.endswith('.warc.gz') for x in files)

        self._verify_content_len(coll_dir, files)
        return files, coll_dir

    def _load_resp_req(self, base_path):
        warcs = os.listdir(base_path)
        assert len(warcs) == 1
        warc = warcs[0]

        stored_resp = None
        stored_req = None

        with open(os.path.join(base_path, warc), 'rb') as fh:
            for rec in ArchiveIterator(fh):
                if rec.rec_type == 'response':
                    stored_resp = rec
                elif rec.rec_type == 'request':
                    stored_req = rec

        assert stored_resp is not None
        assert stored_req is not None
        return stored_req, stored_resp

    def _get_http_only_cookies(self, record):
        non_http_only = None
        http_only = None
        for header in record.http_headers.headers:
            name = header[0].lower()
            if name == 'set-cookie':
                if ExcludeHttpOnlyCookieHeaders.HTTPONLY_RX.search(header[1].lower()):
                    http_only = header
                else:
                    non_http_only = header

        return non_http_only, http_only

    def _verify_content_len(self, base_dir, files):
        for filename in files:
            filename = os.path.join(base_dir, filename)
            with open(filename, 'rb') as fh:
                for record in ArchiveIterator(fh, no_record_parse=True):
                    assert record.http_headers == None
                    assert int(record.rec_headers.get_header('Content-Length')) == record.length
                    assert record.length == len(record.raw_stream.read())

    def test_record_warc_1(self):
        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(to_path(self.root_dir + '/warcs/')))

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/get?foo=bar')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs/', 1)

    def test_record_warc_2(self):
        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(to_path(self.root_dir + '/warcs/')), accept_colls='live')

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/get?foo=bar')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs/', 2)

    def test_error_url(self):
        recorder_app = RecorderApp(self.upstream_url + '01',
                        PerRecordWARCWriter(to_path(self.root_dir + '/warcs/')), accept_colls='live')


        testapp = webtest.TestApp(recorder_app)
        resp = testapp.get('/live/resource?url=http://example.com/', status=400)

        assert resp.json['error'] != ''

        self._test_all_warcs('/warcs/', 2)

    def test_record_cookies_header(self):
        base_path = to_path(self.root_dir + '/warcs/cookiecheck/')
        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(base_path), accept_colls='live')

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/cookies/set%3Fname%3Dvalue%26foo%3Dbar')
        assert b'HTTP/1.1 302' in resp.body

        buff = BytesIO(resp.body)
        record = ArcWarcRecordLoader().parse_record_stream(buff)
        assert ('Set-Cookie', 'name=value; Path=/') in record.http_headers.headers
        assert ('Set-Cookie', 'foo=bar; Path=/') in record.http_headers.headers

        stored_req, stored_resp = self._load_resp_req(base_path)

        assert ('Set-Cookie', 'name=value; Path=/') in stored_resp.http_headers.headers
        assert ('Set-Cookie', 'foo=bar; Path=/') in stored_resp.http_headers.headers

        assert ('X-Other', 'foo') in stored_req.http_headers.headers
        assert ('Cookie', 'boo=far') in stored_req.http_headers.headers

        self._test_all_warcs('/warcs/cookiecheck/', 1)

    def test_record_skip_all_cookies_header(self):
        warc_path = to_path(self.root_dir + '/warcs/cookieskip/')
        header_filter = ExcludeSpecificHeaders(['Set-Cookie', 'Cookie'])
        recorder_app = RecorderApp(self.upstream_url,
                         PerRecordWARCWriter(warc_path, header_filter=header_filter),
                            accept_colls='live')

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/cookies/set%3Fname%3Dvalue%26foo%3Dbar')
        assert b'HTTP/1.1 302' in resp.body

        buff = BytesIO(resp.body)
        record = ArcWarcRecordLoader().parse_record_stream(buff)
        assert ('Set-Cookie', 'name=value; Path=/') in record.http_headers.headers
        assert ('Set-Cookie', 'foo=bar; Path=/') in record.http_headers.headers

        stored_req, stored_resp = self._load_resp_req(warc_path)

        assert ('Set-Cookie', 'name=value; Path=/') not in stored_resp.http_headers.headers
        assert ('Set-Cookie', 'foo=bar; Path=/') not in stored_resp.http_headers.headers

        assert ('X-Other', 'foo') in stored_req.http_headers.headers
        assert ('Cookie', 'boo=far') not in stored_req.http_headers.headers

        self._test_all_warcs('/warcs/cookieskip/', 1)

    def test_record_skip_http_only_cookies_header(self):
        warc_path = to_path(self.root_dir + '/warcs/cookieskip_httponly/')
        header_filter = ExcludeHttpOnlyCookieHeaders()
        recorder_app = RecorderApp(self.upstream_url,
                         PerRecordWARCWriter(warc_path, header_filter=header_filter),
                            accept_colls='live')

        set_cookies = urlencode([('Set-Cookie', 'name=value; Path=/; HttpOnly'),
                                 ('Set-Cookie', 'foo=bar; Path=/')])

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/response-headers' + quote('?' + set_cookies))
        assert b'HTTP/1.1 200' in resp.body

        buff = BytesIO(resp.body)
        record = ArcWarcRecordLoader().parse_record_stream(buff)

        non_http_only, http_only = self._get_http_only_cookies(record)
        # both httponly and other cookies
        assert http_only == ('Set-Cookie', 'name=value; Path=/; HttpOnly')
        assert non_http_only == ('Set-Cookie', 'foo=bar; Path=/')

        stored_req, stored_resp = self._load_resp_req(warc_path)

        non_http_only, http_only = self._get_http_only_cookies(stored_resp)
        # no httponly cookies
        assert http_only == None
        assert non_http_only == ('Set-Cookie', 'foo=bar; Path=/')


        assert ('X-Other', 'foo') in stored_req.http_headers.headers
        assert ('Cookie', 'boo=far') not in stored_req.http_headers.headers

        self._test_all_warcs('/warcs/cookieskip_httponly/', 1)

    def test_record_skip_wrong_coll(self):
        recorder_app = RecorderApp(self.upstream_url,
                        writer=PerRecordWARCWriter(to_path(self.root_dir + '/warcs/')), accept_colls='not-live')

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/get?foo=bar')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs/', 2)

    def test_record_param_user_coll(self):
        warc_path = to_path(self.root_dir + '/warcs/{user}/{coll}/')

        dedup_index = self._get_dedup_index()

        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(warc_path, dedup_index=dedup_index))

        self._test_all_warcs('/warcs/USER/COLL/', None)

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/user-agent',
                            '&param.recorder.user=USER&param.recorder.coll=COLL')

        assert '"user-agent": "{0}"'.format(UA) in resp.text
        #assert b'HTTP/1.1 200 OK' in resp.body
        #assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs/USER/COLL/', 1)

        r = FakeStrictRedis.from_url('redis://localhost/2')

        res = r.zrangebylex('USER:COLL:cdxj', '[org,httpbin)/', '(org,httpbin,')
        assert len(res) == 1

        cdx = CDXObject(res[0])
        assert cdx['urlkey'] == 'org,httpbin)/user-agent'
        assert cdx['mime'] == 'application/json'
        assert cdx['offset'] == '0'
        assert cdx['filename'].startswith(to_path('USER/COLL/'))
        assert cdx['filename'].endswith('.warc.gz')

        warcs = r.hgetall('USER:COLL:warc')
        full_path = to_path(self.root_dir + '/warcs/' + cdx['filename'])
        assert warcs == {cdx['filename'].encode('utf-8'): full_path.encode('utf-8')}

    def test_record_param_user_coll_same_dir(self):
        warc_path = to_path(self.root_dir + '/warcs2/')

        dedup_index = self._get_dedup_index()

        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(warc_path, dedup_index=dedup_index, key_template='{user}:{coll}'))

        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?foo=bar', '&param.recorder.user=USER2&param.recorder.coll=COLL2')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?foo=bar', '&param.recorder.user=USER2&param.recorder.coll=COLL3')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs2', 2)

    def test_record_param_user_coll_revisit(self):
        warc_path = to_path(self.root_dir + '/warcs/{user}/{coll}/')

        dedup_index = self._get_dedup_index()

        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(warc_path, dedup_index=dedup_index))

        self._test_all_warcs('/warcs/USER/COLL/', 1)

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/user-agent',
                                    '&param.recorder.user=USER&param.recorder.coll=COLL')

        assert '"user-agent": "{0}"'.format(UA) in resp.text
        #assert b'HTTP/1.1 200 OK' in resp.body
        #assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs/USER/COLL/', 2)

        # Test Redis CDX
        r = FakeStrictRedis.from_url('redis://localhost/2')

        res = r.zrangebylex('USER:COLL:cdxj', '[org,httpbin)/', '(org,httpbin,')
        assert len(res) == 2

        if b'warc/revisit' in res[0]:
            cdx = CDXObject(res[0])
        else:
            cdx = CDXObject(res[1])

        assert cdx['urlkey'] == 'org,httpbin)/user-agent'
        assert cdx['mime'] == 'warc/revisit'
        assert cdx['offset'] == '0'
        assert cdx['filename'].startswith(to_path('USER/COLL/'))
        assert cdx['filename'].endswith('.warc.gz')

        fullwarc = os.path.join(self.root_dir, 'warcs', cdx['filename'])

        warcs = r.hgetall('USER:COLL:warc')
        assert len(warcs) == 2
        assert warcs[cdx['filename'].encode('utf-8')] == fullwarc.encode('utf-8')

        with open(fullwarc, 'rb') as fh:
            decomp = DecompressingBufferedReader(fh)
            # Test refers-to headers
            status_headers = StatusAndHeadersParser(['WARC/1.0']).parse(decomp)
            assert status_headers.get_header('WARC-Type') == 'revisit'
            assert status_headers.get_header('WARC-Target-URI') == 'http://httpbin.org/user-agent'
            assert status_headers.get_header('WARC-Date') != ''
            assert status_headers.get_header('WARC-Refers-To-Target-URI') == 'http://httpbin.org/user-agent'
            assert status_headers.get_header('WARC-Refers-To-Date') != ''

    def test_record_param_user_coll_skip(self):
        warc_path = to_path(self.root_dir + '/warcs/{user}/{coll}/')

        dedup_index = self._get_dedup_index(dupe_policy=SkipDupePolicy())

        recorder_app = RecorderApp(self.upstream_url,
                        PerRecordWARCWriter(warc_path, dedup_index=dedup_index))

        # No new entries written
        self._test_all_warcs('/warcs/USER/COLL/', 2)

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/user-agent',
                            '&param.recorder.user=USER&param.recorder.coll=COLL')

        assert '"user-agent": "{0}"'.format(UA) in resp.text
        #assert b'HTTP/1.1 200 OK' in resp.body
        #assert b'"foo": "bar"' in resp.body
        self._test_all_warcs('/warcs/USER/COLL/', 2)

        # Test Redis CDX
        r = FakeStrictRedis.from_url('redis://localhost/2')

        res = r.zrangebylex('USER:COLL:cdxj', '[org,httpbin)/', '(org,httpbin,')
        assert len(res) == 2

    def test_record_param_user_coll_write_dupe_no_revisit(self):
        warc_path = to_path(self.root_dir + '/warcs/{user}/{coll}/')

        dedup_index = self._get_dedup_index(dupe_policy=WriteDupePolicy())

        writer = PerRecordWARCWriter(warc_path, dedup_index=dedup_index)
        recorder_app = RecorderApp(self.upstream_url, writer)

        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?foo=bar', '&param.recorder.user=USER&param.recorder.coll=COLL')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        self._test_all_warcs('/warcs/USER/COLL/', 3)

        r = FakeStrictRedis.from_url('redis://localhost/2')

        res = r.zrangebylex('USER:COLL:cdxj', '[org,httpbin)/', '(org,httpbin,')
        assert len(res) == 3

        mimes = [CDXObject(x)['mime'] for x in res]

        assert sorted(mimes) == ['application/json', 'application/json', 'warc/revisit']

        assert len(writer.fh_cache) == 0

    # Keep Open
    def test_record_file_warc_keep_open(self):
        path = to_path(self.root_dir + '/warcs/A.warc.gz')
        writer = MultiFileWARCWriter(path)
        recorder_app = RecorderApp(self.upstream_url, writer)

        resp = self._test_warc_write(recorder_app, 'httpbin.org', '/get?foo=bar')
        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        assert os.path.isfile(path)
        assert len(writer.fh_cache) == 1

        writer.close()
        assert len(writer.fh_cache) == 0

    def test_record_multiple_writes_keep_open(self):
        warc_path = to_path(self.root_dir + '/warcs/FOO/ABC-{hostname}-{timestamp}.warc.gz')

        rel_path = to_path(self.root_dir + '/warcs/')

        dedup_index = self._get_dedup_index(user=False)

        writer = MultiFileWARCWriter(warc_path, dedup_index=dedup_index)
        recorder_app = RecorderApp(self.upstream_url, writer)

        # First Record
        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?foo=bar', '&param.recorder.coll=FOO')

        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body


        # Second Record
        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?boo=far', '&param.recorder.coll=FOO')

        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"boo": "far"' in resp.body

        self._test_all_warcs('/warcs/FOO/', 1)

        # Check two records in WARC
        r = FakeStrictRedis.from_url('redis://localhost/2')
        res = r.zrangebylex('FOO:cdxj', '[org,httpbin)/', '(org,httpbin,')
        assert len(res) == 2

        files, coll_dir = self._test_all_warcs('/warcs/FOO/', 1)
        fullname = coll_dir + files[0]

        cdxout = BytesIO()
        with open(fullname, 'rb') as fh:
            filename = os.path.relpath(fullname, rel_path)
            write_cdx_index(cdxout, fh, filename,
                            cdxj=True, append_post=True, sort=True)

        res = [CDXObject(x) for x in res]

        cdxres = cdxout.getvalue().strip()
        cdxres = cdxres.split(b'\n')
        cdxres = [CDXObject(x) for x in cdxres]

        assert cdxres == res

        assert len(writer.fh_cache) == 1

        writer.close_key(to_path(self.root_dir + '/warcs/FOO/'))

        assert len(writer.fh_cache) == 0

        writer.close()

        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                                '/get?boo=far', '&param.recorder.coll=FOO')

        self._test_all_warcs('/warcs/FOO/', 2)

        warcs = r.hgetall('FOO:warc')
        assert len(warcs) == 2

        writer.close()
        assert len(writer.fh_cache) == 0

    def test_record_multiple_writes_rollover_idle(self):
        warc_path = to_path(self.root_dir + '/warcs/GOO/ABC-{hostname}-{timestamp}.warc.gz')

        rel_path = to_path(self.root_dir + '/warcs/')

        dedup_index = self._get_dedup_index(user=False)

        writer = MultiFileWARCWriter(warc_path, dedup_index=dedup_index, max_idle_secs=0.9)
        recorder_app = RecorderApp(self.upstream_url, writer)

        # First Record
        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?foo=bar', '&param.recorder.coll=GOO')

        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"foo": "bar"' in resp.body

        # Second Record
        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?boo=far', '&param.recorder.coll=GOO')

        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"boo": "far"' in resp.body

        self._test_all_warcs('/warcs/GOO/', 1)

        time.sleep(1.0)
        writer.close_idle_files()

        # Third Record
        resp = self._test_warc_write(recorder_app, 'httpbin.org',
                            '/get?goo=bar', '&param.recorder.coll=GOO')

        assert b'HTTP/1.1 200 OK' in resp.body
        assert b'"goo": "bar"' in resp.body

        self._test_all_warcs('/warcs/GOO/', 2)

        writer.close()
        assert len(writer.fh_cache) == 0

    def test_record_custom_record(self):
        dedup_index = self._get_dedup_index(user=False)

        warc_path = to_path(self.root_dir + '/warcs/meta/meta.warc.gz')

        writer = MultiFileWARCWriter(warc_path, dedup_index=dedup_index)
        recorder_app = RecorderApp(self.upstream_url, writer)

        req_url = '/live/resource/postreq?url=custom://httpbin.org&param.recorder.coll=META&put_record=resource'

        buff = b'Some Data'

        testapp = webtest.TestApp(recorder_app)
        headers = {'content-type': 'text/plain',
                   'WARC-Custom': 'foo'
                  }

        resp = testapp.put(req_url, headers=headers, params=buff)

        assert resp.json['success'] == 'true'
        assert resp.json['WARC-Date'] != ''

        self._test_all_warcs('/warcs/meta', 1)

        r = FakeStrictRedis.from_url('redis://localhost/2')

        warcs = r.hgetall('META:warc')
        assert len(warcs) == 1

        warc_key = os.path.join('meta', 'meta.warc.gz').encode('utf-8')

        with open(warcs[warc_key], 'rb') as fh:
            decomp = DecompressingBufferedReader(fh)
            record = ArcWarcRecordLoader().parse_record_stream(decomp, ensure_http_headers=True)

        status_headers = record.rec_headers
        assert len(record.rec_headers.headers) == 9
        assert status_headers.get_header('WARC-Type') == 'resource'
        assert status_headers.get_header('WARC-Target-URI') == 'custom://httpbin.org'
        assert status_headers.get_header('WARC-Record-ID') != ''
        assert status_headers.get_header('WARC-Date') != ''
        assert status_headers.get_header('WARC-Block-Digest') != ''
        assert status_headers.get_header('WARC-Block-Digest') == status_headers.get_header('WARC-Payload-Digest')
        assert status_headers.get_header('Content-Type') == 'text/plain'
        assert status_headers.get_header('Content-Length') == str(len(buff))
        assert status_headers.get_header('WARC-Custom') == 'foo'

        assert record.raw_stream.read() == buff

        status_headers = record.http_headers
        assert len(record.http_headers.headers) == 2

        assert status_headers.get_header('Content-Type') == 'text/plain'
        assert status_headers.get_header('Content-Length') == str(len(buff))

        writer.close()
        assert len(writer.fh_cache) == 0

    @patch('youtube_dl.YoutubeDL.extract_info', Mock(return_value={'id': 'BfBgWtAIbRc', 'formats': []}))
    def test_record_video_metadata(self):
        warc_path = to_path(self.root_dir + '/warcs/{user}/{coll}/')

        dedup_index = self._get_dedup_index()

        writer = PerRecordWARCWriter(warc_path, dedup_index=dedup_index)
        recorder_app = RecorderApp(self.upstream_url, writer)

        params = {'param.recorder.user': 'USER',
                  'param.recorder.coll': 'VIDEO',
                  'content_type': 'application/vnd.youtube-dl_formats+json'
                 }

        resp = self._test_warc_write(recorder_app,
            'www.youtube.com', '/v/BfBgWtAIbRc', '&' + urlencode(params),
            link_url='metadata://www.youtube.com/v/BfBgWtAIbRc')

        r = FakeStrictRedis.from_url('redis://localhost/2')

        warcs = r.hgetall('USER:VIDEO:warc')
        assert len(warcs) == 1

        filename = list(warcs.values())[0]

        with open(filename, 'rb') as fh:
            decomp = DecompressingBufferedReader(fh)
            record = ArcWarcRecordLoader().parse_record_stream(decomp)

        status_headers = record.rec_headers
        assert status_headers.get_header('WARC-Type') == 'metadata'
        assert status_headers.get_header('Content-Type') == 'application/vnd.youtube-dl_formats+json'
        assert status_headers.get_header('WARC-Block-Digest') != ''
        assert status_headers.get_header('WARC-Block-Digest') == status_headers.get_header('WARC-Payload-Digest')


# ============================================================================
class TestBatchRecorder(LiveServerTests, HttpBinLiveTests, FakeRedisTests,
                       TempDirTests, BaseTestClass):
    @classmethod
    def setup_class(cls):
        super(TestBatchRecorder, cls).setup_class()

        cls.colls_dir = to_path(cls.root_dir + '/colls')
        os.makedirs(os.path.join(cls.colls_dir, 'c1', 'archive'))
        os.makedirs(os.path.join(cls.colls_dir, 'c1', 'indexes'))

        from pywb.manager.batch import BatchManager
        cls.bm = BatchManager(cls.colls_dir)
        cls.upstream_url = 'http://localhost:{0}'.format(cls.server.port)

        cls.warc_path = to_path(
            cls.root_dir + '/colls/{coll}/archive/rec-test.warc.gz')
        cls.batch_dir_template = to_path(
            cls.root_dir + '/colls/{coll}/batches/{batch}/archive/')

    def _make(self, dedup_index=None, poll=0.05):
        writer = MultiFileWARCWriter(self.warc_path, dedup_index=dedup_index,
                                     batch_dir_template=self.batch_dir_template)
        recorder = RecorderApp(self.upstream_url, writer,
                               batch_store=self.bm,
                               batch_poll_interval=poll)
        return writer, recorder, webtest.TestApp(recorder)

    def _post(self, testapp, path='/get?foo=bar', extra=''):
        url = 'http://httpbin.org' + path
        req_url = '/live/resource/postreq?url=' + url + extra
        return testapp.post(
            req_url,
            general_req_data.format(host='httpbin.org', path=path).encode('utf-8'),
            expect_errors=True)

    def _batch_archive(self, batch):
        return os.path.join(self.colls_dir, 'c1', 'batches', batch, 'archive')

    def _public_archive(self):
        return os.path.join(self.colls_dir, 'c1', 'archive')

    def test_batch_routing_admission_gate_counter(self):
        self.bm.create_coll_batch('c1', 'b1')
        writer, recorder, testapp = self._make()

        resp = self._post(testapp, extra='&param.recorder.coll=c1'
                                         '&param.recorder.batch=b1')
        assert resp.status_int == 200
        gevent.sleep(0.3)

        batch_files = os.listdir(self._batch_archive('b1'))
        assert len(batch_files) == 1 and batch_files[0].endswith('.warc.gz')
        assert os.listdir(self._public_archive()) == []
        assert self.bm.capture_count('c1', 'b1') == 0

        # begin/end must be balanced for every accepted capture
        begins = []
        real_begin = self.bm.begin_capture
        real_end = self.bm.end_capture
        self.bm.begin_capture = lambda c, b: begins.append(1) or real_begin(c, b)
        self.bm.end_capture = lambda c, b: (begins.pop(), real_end(c, b))[1] \
            if begins else real_end(c, b)
        try:
            resp = self._post(testapp, path='/get?foo=baz',
                              extra='&param.recorder.coll=c1'
                                    '&param.recorder.batch=b1')
            assert resp.status_int == 200
            gevent.sleep(0.3)
            assert begins == []
        finally:
            self.bm.begin_capture = real_begin
            self.bm.end_capture = real_end

        # sealed batch: rejected, not proxied, nothing new written
        self.bm.seal_batch('c1', 'b1')
        gevent.sleep(0.2)
        mtime = os.path.getmtime(os.path.join(self._batch_archive('b1'),
                                              batch_files[0]))
        resp = self._post(testapp, path='/get?sealed=1',
                          extra='&param.recorder.coll=c1'
                                '&param.recorder.batch=b1')
        assert resp.status_int == 403
        assert 'not open' in resp.json['error_message']
        assert os.listdir(self._batch_archive('b1')) == batch_files
        assert self.bm.capture_count('c1', 'b1') == 0

        # unbatched recording still goes to the public archive
        resp = self._post(testapp, path='/get?pub=1',
                          extra='&param.recorder.coll=c1')
        assert resp.status_int == 200
        gevent.sleep(0.3)
        assert len(os.listdir(self._public_archive())) == 1

        writer.close()

    def test_batch_captures_skip_shared_dedup_index(self):
        r = FakeStrictRedis.from_url('redis://localhost/2')
        r.flushdb()

        dedup_index = WritableRedisIndexer(
            redis_url='redis://localhost/2/{coll}:cdxj',
            file_key_template='{coll}:warc',
            rel_path_template=to_path(self.root_dir + '/colls/c1/archive/'),
            dupe_policy=WriteRevisitDupePolicy())

        self.bm.create_coll_batch('c1', 'b2')
        writer, recorder, testapp = self._make(dedup_index)

        for q in ('/get?dedup=a', '/get?dedup=a'):
            resp = self._post(testapp, path=q,
                              extra='&param.recorder.coll=c1'
                                    '&param.recorder.batch=b2')
            assert resp.status_int == 200
        gevent.sleep(0.3)

        # batch captures never touch the shared redis dedup structures
        assert r.zrange('c1:cdxj', 0, -1) == []
        assert r.hgetall('c1:warc') == {}
        # full response pairs are kept (no revisits)
        files = os.listdir(self._batch_archive('b2'))
        assert len(files) == 1
        rec_types = []
        with open(os.path.join(self._batch_archive('b2'), files[0]), 'rb') as fh:
            for record in ArchiveIterator(fh):
                rec_types.append(record.rec_type)
        assert 'revisit' not in rec_types
        assert rec_types.count('response') == 2

        # unbatched capture populates dedup index as usual
        resp = self._post(testapp, path='/get?dedup=z',
                          extra='&param.recorder.coll=c1')
        assert resp.status_int == 200
        gevent.sleep(0.3)
        assert len(r.zrange('c1:cdxj', 0, -1)) >= 1

        writer.close()

    def test_reaper_closes_sealed_batch_handles_only(self):
        self.bm.create_coll_batch('c1', 'b3')
        writer, recorder, testapp = self._make(poll=0.05)

        resp = self._post(testapp, extra='&param.recorder.coll=c1'
                                         '&param.recorder.batch=b3')
        assert resp.status_int == 200
        gevent.sleep(0.3)

        batch_keys = [k for k in writer.fh_cache if 'batches' in k]
        assert len(batch_keys) == 1

        # a normal (public) capture handle must stay cached
        resp = self._post(testapp, path='/get?keep=1',
                          extra='&param.recorder.coll=c1')
        assert resp.status_int == 200
        gevent.sleep(0.3)
        public_keys = [k for k in writer.fh_cache if 'batches' not in k]
        assert len(public_keys) == 1

        self.bm.seal_batch('c1', 'b3')
        gevent.sleep(0.25)

        assert not [k for k in writer.fh_cache if 'batches' in k]
        # public handles are untouched by the batch reaper
        assert all(k in writer.fh_cache for k in public_keys)

        # released handle allows moving the batch WARC (required on Windows)
        warc = os.path.join(self._batch_archive('b3'),
                            os.listdir(self._batch_archive('b3'))[0])
        backup = warc + '.bak'
        os.rename(warc, backup)
        os.rename(backup, warc)

        writer.close()

    def test_inflight_admission_count_blocks_seal_operations(self):
        from types import SimpleNamespace
        from io import BytesIO
        from warcio.statusandheaders import StatusAndHeaders
        from warcio.warcwriter import WARCWriter
        from pywb.manager.batch import BatchError

        # deterministic slow upstream: a complete WARC response record whose
        # raw bytes become readable only after a gevent event is set
        url = 'http://slow.example/x'
        buf = BytesIO()
        warc_writer = WARCWriter(buf, gzip=False)
        warc_writer.write_record(warc_writer.create_warc_record(
            url, 'response', payload=BytesIO(b'hello slow batch'),
            http_headers=StatusAndHeaders(
                'HTTP/1.1 200 OK',
                [('Content-Type', 'text/plain')])))
        warc_bytes = buf.getvalue()

        release = gevent.event.Event()

        class SlowRaw(object):
            def __init__(self, data):
                self.data = data
                self.pos = 0

            def read(self, n=-1):
                if self.pos == 0:
                    release.wait()
                if self.pos >= len(self.data):
                    return b''
                if n is None or n < 0:
                    n = len(self.data)
                chunk = self.data[self.pos:self.pos + n]
                self.pos += len(chunk)
                return chunk

            def close(self):
                pass

        def fake_request(*args, **kwargs):
            return SimpleNamespace(status_code=200,
                                   headers={'Content-Type': 'application/warc'},
                                   raw=SlowRaw(warc_bytes),
                                   raise_for_status=lambda: None)

        self.bm.create_coll_batch('c1', 'b6')
        writer, recorder, testapp = self._make(poll=0.05)

        result = {}
        req_url = ('/live/resource/postreq?url={0}'
                   '&param.recorder.coll=c1&param.recorder.batch=b6'
                   ).format(url)
        req_body = general_req_data.format(
            host='slow.example', path='/x').encode('utf-8')

        def client():
            try:
                resp = testapp.post(req_url, req_body)
                result['status'] = resp.status_int
                result['body'] = resp.body
            except Exception as exc:
                result['error'] = exc

        try:
            with patch('pywb.recorder.recorderapp.requests') as fake_requests:
                fake_requests.request.side_effect = fake_request

                g = gevent.spawn(client)
                gevent.sleep(0.5)

                # admitted and stuck buffering the slow response -> counted
                assert self.bm.capture_count('c1', 'b6') == 1

                self.bm.seal_batch('c1', 'b6')
                gevent.sleep(0.2)

                # neither publish nor discard may proceed while in flight
                with pytest.raises(BatchError):
                    self.bm.discard_batch('c1', 'b6', wait=0.3, poll=0.05)
                with pytest.raises(BatchError):
                    self.bm.publish_batch('c1', 'b6', wait=0.3, poll=0.05)
                assert self.bm.get_state('c1', 'b6') == 'sealed'

                release.set()
                g.join(timeout=5)

            assert 'error' not in result
            assert result['status'] == 200
            assert self.bm.wait_drained('c1', 'b6', timeout=5.0)

            # the admitted capture was written despite the seal
            warcs = os.listdir(self._batch_archive('b6'))
            assert len(warcs) == 1 and warcs[0].endswith('.warc.gz')

            # discard can now complete and no payload is resurrected
            writer.close()
            gevent.sleep(0.2)
            assert self.bm.discard_batch('c1', 'b6', wait=5.0) is True
            assert os.listdir(self.bm.batch_dir('c1', 'b6')) == \
                ['batch.yaml']
        finally:
            writer.close()

    def test_put_record_batch_gate(self):
        self.bm.create_coll_batch('c1', 'b4')
        self.bm.seal_batch('c1', 'b4')
        self.bm.create_coll_batch('c1', 'b5')
        writer, recorder, testapp = self._make()

        url = ('/live/resource/postreq?put_record=resource'
               '&url=custom://example.com/data'
               '&param.recorder.coll=c1&param.recorder.batch=b4')
        resp = testapp.put(url, params=b'payload',
                           headers={'content-type': 'text/plain'},
                           expect_errors=True)
        assert resp.status_int == 403
        gevent.sleep(0.2)
        assert os.listdir(self._batch_archive('b4')) == []
        assert self.bm.capture_count('c1', 'b4') == 0

        url = url.replace('batch=b4', 'batch=b5')
        resp = testapp.put(url, params=b'payload',
                           headers={'content-type': 'text/plain'})
        assert resp.status_int == 200
        gevent.sleep(0.3)
        assert len(os.listdir(self._batch_archive('b5'))) == 1
        assert self.bm.capture_count('c1', 'b5') == 0

        writer.close()
