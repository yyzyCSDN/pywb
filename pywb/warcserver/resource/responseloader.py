import base64
import datetime
import hashlib
import json
import logging
import os
import tempfile
import traceback
import uuid
from io import BytesIO

import six
from requests.models import PreparedRequest
from six.moves.urllib.parse import quote, unquote, urljoin, urlsplit
from warcio.statusandheaders import StatusAndHeaders, StatusAndHeadersParser
from warcio.timeutils import (
    datetime_to_http_date,
    datetime_to_iso_date,
    datetime_to_timestamp,
    http_date_to_datetime,
    iso_date_to_datetime,
    iso_date_to_timestamp,
    timestamp_to_datetime
)
from warcio.utils import to_native_str

from pywb.utils.canonicalize import canonicalize
from pywb.utils.format import ParamFormatter
from pywb.utils.io import StreamIter, call_release_conn, compress_gzip_iter, no_except_close
from pywb.utils.memento import MementoUtils
from pywb.utils.refresh import parse_refresh
from pywb.utils.wbexception import LiveResourceException, RecordUnavailableException
from pywb.warcserver.http import DefaultAdapters
from pywb.warcserver.liveurlfilter import LiveUrlFilter
from pywb.warcserver.resource.pathresolvers import DefaultResolverMixin
from pywb.warcserver.resource.resolvingloader import ResolvingLoader
from pywb.warcserver.vrref import VRReferenceCodec, digest_algorithm, digest_value

logger = logging.getLogger('warcserver')


#=============================================================================
class BaseLoader(object):
    def __call__(self, cdx, params):
        entry = self.load_resource(cdx, params)
        if not entry:
            return None, None

        compress = params.get('compress') == 'gzip'

        warc_headers, other_headers, stream = entry

        source = self._get_source_id(cdx)

        out_headers = {}
        out_headers['Warcserver-Type'] = 'warc'
        out_headers['Content-Type'] = 'application/warc-record'

        if params.get('recorder_skip'):
            out_headers['Recorder-Skip'] = '1'
            cdx['recorder_skip'] = '1'

        out_headers['Warcserver-Cdx'] = to_native_str(cdx.to_cdxj().rstrip())
        out_headers['Warcserver-Source-Coll'] = to_native_str(source)

        # verifiable replay reference minted for this exact local capture
        vr_ref = cdx.get('_vr_ref')
        if vr_ref:
            out_headers['Warcserver-Vr-Ref'] = to_native_str(vr_ref)

        if not warc_headers:
            if other_headers:
                out_headers['Link'] = other_headers.get('Link')
                out_headers['Memento-Datetime'] = other_headers.get('Memento-Datetime')
                if not compress:
                    known_length = other_headers.get('Content-Length')
                    if known_length:
                        out_headers['Content-Length'] = known_length

            return out_headers, StreamIter(stream, closer=call_release_conn)

        target_uri = warc_headers.get_header('WARC-Target-URI')

        out_headers['WARC-Target-URI'] = target_uri

        out_headers['Link'] = MementoUtils.make_link(target_uri, 'original')

        memento_dt = iso_date_to_datetime(warc_headers.get_header('WARC-Date'))
        out_headers['Memento-Datetime'] = datetime_to_http_date(memento_dt)

        warc_headers_buff = warc_headers.to_bytes()

        # don't set length, just stream as is in case it is wrong
        #if not compress:
        #    lenset = self._set_content_len(warc_headers.get_header('Content-Length'),
        #                                 out_headers,
        #                                 len(warc_headers_buff))
        #else:
        #    lenset = False

        streamiter = StreamIter(stream,
                                header1=warc_headers_buff,
                                header2=other_headers,
                                closer=call_release_conn)

        if compress:
            streamiter = compress_gzip_iter(streamiter)
            out_headers['Content-Encoding'] = 'gzip'

        #if not lenset:
        #    out_headers['Transfer-Encoding'] = 'chunked'
        #    streamiter = chunk_encode_iter(streamiter)

        return out_headers, streamiter

    def _get_source_id(self, cdx):
        return quote(cdx.get('source', ''), safe=':/')

    def _set_content_len(self, content_len_str, headers, existing_len):
        # Try to set content-length, if it is available and valid
        try:
            content_len = int(content_len_str)
        except (ValueError, TypeError):
            content_len = -1

        if content_len >= 0:
            content_len += existing_len
            headers['Content-Length'] = str(content_len)
            return True

        return False

    def _check_url_allowed(self, load_url, cdx):
        if not LiveUrlFilter.is_allowed(load_url, cdx):
            raise LiveResourceException('Blocked by live_url_filter', url=load_url)

    def raise_on_self_redirect(self, params, cdx, status_code, location_url,
                               refresh=None):
        """
        Check if response is a 3xx redirect, or an immediate Refresh, to the same url
        If so, reject this capture to avoid causing redirect loop
        """
        if cdx.get('is_live'):
            return

        if not status_code.startswith('3') or status_code == '304':
            location_url = None

        if not location_url:
            location_url = self._get_immediate_refresh_url(cdx, refresh)

        request_url = params['url'].lower()
        if not location_url:
            return


        location_url = location_url.lower()
        if location_url.startswith('/'):
            host = urlsplit(cdx['url']).netloc
            location_url = host + location_url

        location_url = location_url.split('://', 1)[-1].rstrip('/')
        request_url = request_url.split('://', 1)[-1].rstrip('/')

        self_redir = False
        orig_key = params.get('sr-urlkey') or cdx['urlkey']

        if request_url == location_url:
            self_redir = True

        # if new location canonicalized matches old key, also self-redirect
        elif canonicalize(location_url) == orig_key:
            self_redir = True

        if self_redir:
            msg = 'Self Redirect {0} -> {1}'
            msg = msg.format(request_url, location_url)
            params['sr-urlkey'] = orig_key
            raise LiveResourceException(msg)

    @staticmethod
    def _get_immediate_refresh_url(cdx, refresh):
        """
        Return the absolute url of a Refresh with no delay, which the browser
        follows like a redirect, or None otherwise
        """
        res = parse_refresh(refresh)
        if not res or res[0] != 0:
            return None

        return urljoin(cdx['url'], res[1])

    @staticmethod
    def _make_warc_id(id_=None):
        if not id_:
            id_ = uuid.uuid1()
        return '<urn:uuid:{0}>'.format(id_)


#=============================================================================
class WARCPathLoader(DefaultResolverMixin, BaseLoader):
    def __init__(self, paths, cdx_source, vr_codec=None):
        self.paths = paths

        self.resolvers = self.make_resolvers(self.paths)

        self.resolve_loader = ResolvingLoader(self.resolvers,
                                              no_record_parse=False)

        self.headers_parser = StatusAndHeadersParser([], verify=False)

        self.cdx_source = cdx_source

        # codec used to mint verifiable replay references for local captures
        self.vr_codec = vr_codec or VRReferenceCodec()

    def load_resource(self, cdx, params):
        if cdx.get('_cached_result'):
            return cdx.get('_cached_result')

        if not cdx.get('filename') or cdx.get('offset') is None:
            return None

        orig_source = cdx.get('source', '').split(':')[0]
        formatter = ParamFormatter(params, orig_source)
        cdx._formatter = formatter

        def local_index_query(local_params):
            for n, v in six.iteritems(params):
                if n.startswith('param.'):
                    local_params[n] = v

            cdx_iter, errs = self.cdx_source(local_params)
            for cdx in cdx_iter:
                cdx._formatter = formatter
                yield cdx

        failed_files = []
        headers, payload = (self.resolve_loader.
                             load_headers_and_payload(cdx,
                                                      failed_files,
                                                      local_index_query))

        # mint before _assemble_entry(), which rewrites the payload record's
        # target uri/date headers to the (revisit) header record's values
        self._mint_vr_ref(cdx, params, headers, payload)

        entry = self._assemble_entry(cdx, params, headers, payload)

        return entry

    def load_pinned(self, header_cdx, payload_cdx, claims, params):
        """Replay the exact records described by a verifiable replay
        reference, without any candidate search.

        ``header_cdx`` and ``payload_cdx`` are the rows of the *current*
        index that exactly match every locator of the signed reference; the
        physical records are loaded from their locators and their identity
        and payload fingerprint are verified before anything is replayed.
        """
        # path resolvers expand collection templates (eg. '{coll}') from the
        # row formatter, exactly as in ordinary replay
        for row in (header_cdx, payload_cdx):
            if row is not None:
                row._formatter = ParamFormatter(params,
                                                row.get('source', '').split(':')[0])

        failed_files = []
        headers = self.resolve_loader.load_pinned_record(header_cdx,
                                                          failed_files)

        if payload_cdx is not None:
            payload = self.resolve_loader.load_pinned_record(payload_cdx,
                                                              failed_files)
        else:
            payload = headers

        try:
            self._verify_pinned(claims, headers, payload)
            entry = self._assemble_entry(header_cdx, params, headers, payload)
        except RecordUnavailableException:
            no_except_close(headers.raw_stream)
            if payload is not headers:
                no_except_close(payload.raw_stream)
            raise

        # echo the reference instead of re-minting: the replay stays bound
        # to exactly this token
        header_cdx['_vr_ref'] = params.get('vrref')
        header_cdx['_cached_result'] = entry

        return self(header_cdx, params)

    @staticmethod
    def _record_ts(record):
        warc_date = record.rec_headers.get_header('WARC-Date')
        if warc_date:
            return iso_date_to_timestamp(warc_date)
        return ''

    def _verify_pinned(self, claims, headers, payload):
        """Verify that the loaded records are still exactly the records the
        reference was minted for, and that the actual payload matches the
        bound fingerprint.  Spools the payload while hashing it so a digest
        mismatch is reported before a single byte is replayed."""
        h_uri = headers.rec_headers.get_header('WARC-Target-URI')
        if h_uri != claims['url']:
            raise RecordUnavailableException(
                'Verifiable replay reference unavailable: header record '
                'target uri changed ({0} != {1})'.format(h_uri, claims['url']))

        h_ts = self._record_ts(headers)
        if h_ts and h_ts != claims['ts']:
            raise RecordUnavailableException(
                'Verifiable replay reference unavailable: header record '
                'date changed ({0} != {1})'.format(h_ts, claims['ts']))

        if claims['rec_type'] == 'revisit':
            if headers.rec_type != 'revisit':
                raise RecordUnavailableException(
                    'Verifiable replay reference unavailable: bound record '
                    'is no longer a revisit')

            if payload is not headers:
                p_uri = payload.rec_headers.get_header('WARC-Target-URI')
                if p_uri != claims['p_url']:
                    raise RecordUnavailableException(
                        'Verifiable replay reference unavailable: revisit '
                        'donor target uri changed ({0} != {1})'.format(
                            p_uri, claims['p_url']))

                p_ts = self._record_ts(payload)
                if p_ts and p_ts != claims['p_ts']:
                    raise RecordUnavailableException(
                        'Verifiable replay reference unavailable: revisit '
                        'donor date changed ({0} != {1})'.format(
                            p_ts, claims['p_ts']))

                # the revisit header must still point at this donor
                ref_uri = headers.rec_headers.get_header(
                    'WARC-Refers-To-Target-URI')
                if ref_uri and ref_uri != p_uri:
                    raise RecordUnavailableException(
                        'Verifiable replay reference unavailable: revisit no '
                        'longer refers to the bound donor')
        else:
            if headers.rec_type == 'revisit':
                raise RecordUnavailableException(
                    'Verifiable replay reference unavailable: bound record '
                    'is now a revisit')

        # redirect revisit optimization: the header record carries the 3xx
        # and is replayed with a zero-length body, no donor record is bound
        # (p == h), so there is no payload fingerprint to verify -- the
        # record locator and identity checks above pin the actual record
        if payload is headers and claims['rec_type'] == 'revisit':
            http_headers = headers.http_headers
            status_code = http_headers and http_headers.get_statuscode()
            if status_code and status_code.startswith('3'):
                return

        self._verify_payload_digest(payload, claims['digest'])

    @staticmethod
    def _verify_payload_digest(record, expected_digest):
        expected = digest_value(expected_digest)
        algo = digest_algorithm(expected_digest)

        spool = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode='w+b')
        hasher = hashlib.new(algo)
        try:
            while True:
                buff = record.raw_stream.read(65536)
                if not buff:
                    break
                hasher.update(buff)
                spool.write(buff)

            actual = base64.b32encode(hasher.digest()).decode('ascii').rstrip('=')
            if actual.upper() != expected.upper():
                raise RecordUnavailableException(
                    'Verifiable replay reference unavailable: payload '
                    'fingerprint does not match ({0}: {1} != {2})'.format(
                        algo, actual, expected))
        finally:
            spool.seek(0)
            record.raw_stream = spool

    def _assemble_entry(self, cdx, params, headers, payload):
        """Build the (warc_headers, http_headers_buff, payload_stream) tuple
        returned to BaseLoader from the resolved/verified header and payload
        records."""
        http_headers_buff = None

        if payload.rec_type in ('response', 'revisit'):
            status = cdx.get('status')

            try:
                orig_size = payload.raw_stream.tell()
            except:
                orig_size = 0

            http_headers = headers.http_headers or payload.http_headers

            refresh = http_headers and http_headers.get_header('Refresh')

            # if status is not set and not, 2xx, 4xx, 5xx, or a Refresh is set,
            # go through self-redirect check just in case
            if refresh or not status or not status.startswith(('2', '4', '5')):
                try:
                    self.raise_on_self_redirect(params, cdx,
                                                http_headers.get_statuscode(),
                                                http_headers.get_header('Location'),
                                                refresh)
                except LiveResourceException:
                    no_except_close(headers.raw_stream)
                    no_except_close(payload.raw_stream)
                    raise

            http_headers_buff = http_headers and http_headers.to_bytes()

            # if new http_headers_buff is different length,
            # attempt to adjust content-length on the WARC record
            if http_headers and orig_size and len(http_headers_buff) != orig_size:
                orig_cl = payload.rec_headers.get_header('Content-Length')
                if orig_cl:
                    new_cl = int(orig_cl) + (len(http_headers_buff) - orig_size)
                    payload.rec_headers.replace_header('Content-Length', str(new_cl))

        warc_headers = payload.rec_headers

        if headers != payload:
            warc_headers.replace_header('WARC-Refers-To-Target-URI',
                     payload.rec_headers.get_header('WARC-Target-URI'))

            warc_headers.replace_header('WARC-Refers-To-Date',
                     payload.rec_headers.get_header('WARC-Date'))

            warc_headers.replace_header('WARC-Target-URI',
                     headers.rec_headers.get_header('WARC-Target-URI'))

            warc_headers.replace_header('WARC-Date',
                     headers.rec_headers.get_header('WARC-Date'))
            no_except_close(headers.raw_stream)

        return (warc_headers, http_headers_buff, payload.raw_stream)

    def _mint_vr_ref(self, cdx, params, headers, payload):
        """Mint the verifiable replay reference bound to the actually loaded
        header and payload records (including a resolved donor for revisits)
        and stash it on the cdx so BaseLoader can expose it as a response
        header."""
        if not self.vr_codec or cdx.get('_vr_ref'):
            return
        coll = params.get('_coll')
        if coll is None:
            return
        try:
            header_loc = (cdx.get('filename'),
                          str(cdx.get('offset')),
                          str(cdx.get('length', '-')))

            payload_loc = (getattr(payload, 'source_filename', None) or
                           cdx.get('filename'),
                           str(getattr(payload, 'source_offset', None) or
                               cdx.get('offset')),
                           str(getattr(payload, 'source_length', None) or
                               cdx.get('length', '-')))

            payload_uri = payload.rec_headers.get_header('WARC-Target-URI') or cdx['url']
            payload_ts = self._record_ts(payload) or cdx['timestamp']

            cdx['_vr_ref'] = self.vr_codec.mint(
                coll=coll,
                url=cdx['url'],
                timestamp=cdx['timestamp'],
                digest=cdx.get('digest', ''),
                rec_type=headers.rec_type or payload.rec_type or 'response',
                header_loc=header_loc,
                payload_loc=payload_loc,
                payload_url=payload_uri,
                payload_ts=payload_ts)
        except Exception as e:
            # minting a reference must never break ordinary replay
            if logger.isEnabledFor(logging.DEBUG):
                traceback.print_exc()
            logger.debug('could not mint verifiable replay reference: ' + str(e))

    def __str__(self):
        return  'WARCPathLoader'


#=============================================================================
class LiveWebLoader(BaseLoader):
    SKIP_HEADERS = ('link',
                    'memento-datetime',
                    'content-location',
                    'x-archive')

    UNREWRITE_HEADERS = ('location', 'content-location')

    VIDEO_MIMES = ('application/x-mpegURL',
                   'application/vnd.apple.mpegurl',
                   'application/dash+xml')

    def __init__(self, forward_proxy_prefix=None, adapter=None, use_local_file_load=False):
        self.forward_proxy_prefix = forward_proxy_prefix

        # indicates if WARCs can be loaded locally, even if we get to this fallback
        self.use_local_file_load = use_local_file_load

        socks_host = os.environ.get('SOCKS_HOST')
        socks_port = os.environ.get('SOCKS_PORT', 9050)
        if socks_host and socks_port:
            self.socks_proxy = 'socks5h://{0}:{1}'.format(socks_host, socks_port)
        else:
            self.socks_proxy = None

    def load_resource(self, cdx, params):
        if cdx.get('filename') and cdx.get('offset') is not None:
            # if loading locally, skip here so can retry
            # in case of revisit
            if self.use_local_file_load:
                return None

        load_url = cdx.get('load_url')
        if not load_url:
            return None

        if params.get('content_type') == VideoLoader.CONTENT_TYPE:
            return None

        if self.forward_proxy_prefix and not cdx.get('is_live'):
            load_url = self.forward_proxy_prefix + load_url

        input_req = params['_input_req']

        req_headers = input_req.get_req_headers()

        dt = timestamp_to_datetime(cdx['timestamp'])

        if cdx.get('memento_url'):
            req_headers['Accept-Datetime'] = datetime_to_http_date(dt)

        method = input_req.get_req_method()
        data = input_req.get_req_body()

        p = PreparedRequest()
        try:
            p.prepare_url(load_url, None)
        except Exception:
            raise LiveResourceException(load_url)
        p.prepare_headers(None)
        p.prepare_auth(None, load_url)

        auth = p.headers.get('Authorization')
        if auth:
            req_headers['Authorization'] = auth

        load_url = p.url

        # host is set to the actual host for live loading
        # ensure it is set to the load_url host
        if not cdx.get('is_live'):
            #req_headers.pop('Host', '')
            req_headers['Host'] = urlsplit(p.url).netloc

            referrer = cdx.get('set_referrer')
            if referrer:
                req_headers['Referer'] = referrer

        upstream_res = self._do_request_with_redir_check(method, load_url,
                                                         data, req_headers,
                                                         params, cdx)

        memento_dt = upstream_res.headers.get('Memento-Datetime')
        if memento_dt:
            dt = http_date_to_datetime(memento_dt)
            cdx['timestamp'] = datetime_to_timestamp(dt)
        elif cdx.get('memento_url'):
        # if 'memento_url' set and no Memento-Datetime header present
        # then its an error
            no_except_close(upstream_res)
            return None

        agg_type = upstream_res.headers.get('Warcserver-Type')
        if agg_type == 'warc':
            cdx['source'] = unquote(upstream_res.headers.get('Warcserver-Source-Coll'))
            return None, upstream_res.headers, upstream_res

        if upstream_res.version == 11:
            version = '1.1'
        else:
            version = '1.0'

        status = 'HTTP/{version} {status} {reason}\r\n'
        status = status.format(version=version,
                               status=upstream_res.status,
                               reason=upstream_res.reason)

        http_headers_buff = status

        orig_resp = upstream_res._original_response

        try:  #pragma: no cover
        #PY 3
            resp_headers = orig_resp.headers._headers
            for n, v in resp_headers:
                nl = n.lower()
                if nl in self.SKIP_HEADERS:
                    continue

                if nl in self.UNREWRITE_HEADERS:
                    v = self.unrewrite_header(cdx, v)

                http_headers_buff += n + ': ' + v + '\r\n'

            http_headers_buff += '\r\n'

            try:
                # http headers could be encoded as utf-8 (though non-standard)
                # first try utf-8 encoding
                http_headers_buff = http_headers_buff.encode('utf-8')
            except:
                # then, fall back to latin-1
                http_headers_buff = http_headers_buff.encode('latin-1')

        except:  #pragma: no cover
        #PY 2
            resp_headers = orig_resp.msg.headers

            for line in resp_headers:
                n, v = line.split(':', 1)
                n = n.lower()
                v = v.strip()

                if n in self.SKIP_HEADERS:
                    continue

                new_v = v
                if n in self.UNREWRITE_HEADERS:
                    new_v = self.unrewrite_header(cdx, v)

                if new_v != v:
                    http_headers_buff += n + ': ' + new_v + '\r\n'
                else:
                    http_headers_buff += line

            # if python2, already byte headers, so leave as is
            http_headers_buff += '\r\n'

        try:
            fp = upstream_res._fp.fp
            if hasattr(fp, 'raw'):  #pragma: no cover
                fp = fp.raw
            remote_ip = fp._sock.getpeername()[0]
        except:  #pragma: no cover
            remote_ip = None

        warc_headers = {}

        warc_headers['WARC-Type'] = 'response'
        warc_headers['WARC-Record-ID'] = self._make_warc_id()
        warc_headers['WARC-Target-URI'] = cdx['url']
        warc_headers['WARC-Date'] = datetime_to_iso_date(dt)

        if not cdx.get('is_live'):
            now = datetime.datetime.now(datetime.timezone.utc)
            warc_headers['WARC-Source-URI'] = cdx.get('load_url')
            warc_headers['WARC-Creation-Date'] = datetime_to_iso_date(now)

        if remote_ip:
            warc_headers['WARC-IP-Address'] = remote_ip

        ct = upstream_res.headers.get('Content-Type')
        if ct:
            metadata = self.get_custom_metadata(ct, dt)
            if metadata:
                warc_headers['WARC-JSON-Metadata'] = json.dumps(metadata)

        warc_headers['Content-Type'] = 'application/http; msgtype=response'

        if method == 'HEAD':
            content_len = 0
        else:
            content_len = upstream_res.headers.get('Content-Length', -1)

        self._set_content_len(content_len,
                              warc_headers,
                              len(http_headers_buff))

        warc_headers = StatusAndHeaders('WARC/1.0', warc_headers.items())
        return (warc_headers, http_headers_buff, upstream_res)

    def unrewrite_header(self, cdx, value):
        if not value:
            return value

        if cdx.get('is_live'):
            return value

        inx = value.find('/http', 1)
        if inx < 1:
            return value

        return value[inx + 1:]

    def _do_request_with_redir_check(self, method, load_url,
                                     data, req_headers, params, cdx):

        self._check_url_allowed(load_url, cdx)
        upstream_res = self._do_request(method, load_url,
                                        data, req_headers, params,
                                        cdx.get('is_live'))

        if cdx.get('is_live'):
            return upstream_res

        self_redir_count = 0

        while True:
            try:
                location = upstream_res.headers.get('Location')
                self.raise_on_self_redirect(params, cdx,
                                            str(upstream_res.status),
                                            self.unrewrite_header(cdx, location))

                break

            except LiveResourceException as e:
                if load_url == location or self_redir_count >= 3:
                    raise

                load_url = location
                self._check_url_allowed(load_url, cdx)
                upstream_res = self._do_request(method, load_url, data,
                                                req_headers, params, cdx.get('is_live'))
                self_redir_count += 1

        return upstream_res

    def _do_request(self, method, load_url, data, req_headers, params, is_live):
        adapter = DefaultAdapters.live_adapter if is_live else DefaultAdapters.remote_adapter
        max_retries = adapter.max_retries

        # get either the poolmanager or proxy manager to handle this connection
        if self.socks_proxy and not os.environ.get('SOCKS_DISABLE'):
            manager = adapter.proxy_manager_for(self.socks_proxy)
        else:
            manager = adapter.poolmanager

        upstream_res = None
        try:
            upstream_res = manager.urlopen(method=method,
                                           url=load_url,
                                           body=data,
                                           headers=req_headers,
                                           redirect=False,
                                           assert_same_host=False,
                                           preload_content=False,
                                           decode_content=False,
                                           retries=max_retries,
                                           timeout=params.get('_timeout'))

            return upstream_res

        except Exception as e:
            if upstream_res:
                no_except_close(upstream_res)
            if logger.isEnabledFor(logging.DEBUG):
                import traceback
                traceback.print_exc()
                logger.debug('FAILED: ' + method + ' ' + load_url + ': ' + str(e))

            raise LiveResourceException(load_url)

    def get_custom_metadata(self, content_type, dt):
        if content_type in self.VIDEO_MIMES:
            return {'adaptive_max_resolution': 1280 * 720,
                    'adaptive_max_bandwidth': 2000000}

    def __str__(self):
        return  'LiveWebLoader'


#=============================================================================
class VideoLoader(BaseLoader):
    CONTENT_TYPE = 'application/vnd.youtube-dl_formats+json'

    def __init__(self):
        try:
            from youtube_dl import YoutubeDL as YoutubeDL
        except ImportError:
            self.ydl = None
            return

        self.ydl = YoutubeDL(dict(simulate=True, quiet=True,
                                  youtube_include_dash_manifest=False))

        self.ydl.add_default_info_extractors()

    def load_resource(self, cdx, params):
        load_url = cdx.get('load_url')
        if not load_url:
            return None

        if params.get('content_type') != self.CONTENT_TYPE:
            return None

        if not self.ydl:
            return None

        self._check_url_allowed(load_url, cdx)

        info = self.ydl.extract_info(load_url)
        info_buff = json.dumps(info)
        info_buff = info_buff.encode('utf-8')

        warc_headers = {}

        schema, rest = load_url.split('://', 1)
        target_url = 'metadata://' + rest

        dt = timestamp_to_datetime(cdx['timestamp'])

        warc_headers['WARC-Type'] = 'metadata'
        warc_headers['WARC-Record-ID'] = self._make_warc_id()
        warc_headers['WARC-Target-URI'] = target_url
        warc_headers['WARC-Date'] = datetime_to_iso_date(dt)
        warc_headers['Content-Type'] = self.CONTENT_TYPE
        warc_headers['Content-Length'] = str(len(info_buff))

        warc_headers = StatusAndHeaders('WARC/1.0', warc_headers.items())

        return warc_headers, None, BytesIO(info_buff)

