from pywb.utils.wbexception import BadRequestException, WbException, AccessException
from pywb.utils.wbexception import NotFoundException, RecordUnavailableException
from pywb.utils.memento import MementoUtils

from warcio.recordloader import ArchiveLoadFailed

from pywb.warcserver.index.cdxobject import CDXException
from pywb.warcserver.index.fuzzymatcher import FuzzyMatcher
from pywb.warcserver.resource.responseloader import  WARCPathLoader, LiveWebLoader, VideoLoader
from pywb.warcserver.vrref import VRReferenceCodec, normalize_digest

import six
import logging
import traceback


logger = logging.getLogger('warcserver')


#=============================================================================
def to_cdxj(cdx_iter, fields, params):
    content_type = 'text/x-cdxj'
    return content_type, (cdx.to_cdxj(fields) for cdx in cdx_iter)

def to_json(cdx_iter, fields, params):
    content_type = 'text/x-ndjson'
    return content_type, (cdx.to_json(fields) for cdx in cdx_iter)

def to_text(cdx_iter, fields, params):
    content_type = 'text/plain'
    return content_type, (cdx.to_text(fields) for cdx in cdx_iter)

def to_link(cdx_iter, fields, params):
    content_type = 'application/link-format'
    return content_type, MementoUtils.make_timemap(cdx_iter, params)


#=============================================================================
class IndexHandler(object):
    OUTPUTS = {
        'cdxj': to_cdxj,
        'json': to_json,
        'text': to_text,
        'link': to_link,
    }

    DEF_OUTPUT = 'cdxj'

    def __init__(self, index_source, opts=None, *args, **kwargs):
        self.index_source = index_source
        self.opts = opts or {}
        self.fuzzy = FuzzyMatcher(kwargs.get('rules_file'))
        self.access_checker = kwargs.get('access_checker')

    def get_supported_modes(self):
        return dict(modes=['list_sources', 'index'])

    def _load_index_source(self, params):
        url = params.get('url')
        if not url:
            errs = dict(last_exc=BadRequestException('The "url" param is required'))
            return None, errs

        input_req = params.get('_input_req')
        if input_req:
            params['alt_url'] = input_req.include_method_query(url)

        cdx_iter = self.fuzzy(self.index_source, params)

        acl_user = params['_input_req'].env.get("HTTP_X_PYWB_ACL_USER")

        if self.access_checker:
            cdx_iter = self.access_checker(cdx_iter, acl_user)

        return cdx_iter

    def __call__(self, params):
        mode = params.get('mode', 'index')
        if mode == 'list_sources':
            return {}, self.index_source.get_source_list(params), {}

        if mode != 'index':
            return {}, self.get_supported_modes(), {}

        output = params.get('output', self.DEF_OUTPUT)
        fields = params.get('fields')
        if not fields:
            fields = params.get('fl')

        if fields and isinstance(fields, str):
            fields = fields.split(',')

        handler = self.OUTPUTS.get(output)
        if not handler:
            errs = dict(last_exc=BadRequestException('output={0} not supported'.format(output)))
            return None, None, errs

        cdx_iter = None
        try:
            cdx_iter, errs = self._load_index_source(params)
        except BadRequestException as e:
            errs = dict(last_exc=e)
        if not cdx_iter:
            return None, None, errs

        content_type, res = handler(cdx_iter, fields, params)
        out_headers = {'Content-Type': content_type}

        first_line = None
        try:
            # raise exceptions early so that they can be handled properly
            first_line = next(res)
        except StopIteration:
            pass
        except CDXException as e:
            errs = dict(last_exc=e)
            return None, None, errs

        def check_str(first_line, lines):
            if first_line is not None:
                if isinstance(first_line, six.text_type):
                    first_line = first_line.encode('utf-8')
                yield first_line
            for line in lines:
                if isinstance(line, six.text_type):
                    line = line.encode('utf-8')
                yield line

        return out_headers, check_str(first_line, res), errs


#=============================================================================
class ResourceHandler(IndexHandler):
    # default limit for resource lookups with closest and no explicit limit:
    # only the first closest captures are usually loaded, so avoid sorting
    # and keeping all the captures of the url (applied in CDXQuery.limit)
    CLOSEST_LIMIT = 100

    def __init__(self, index_source, resource_loaders, vr_codec=None, **kwargs):
        super(ResourceHandler, self).__init__(index_source, **kwargs)
        self.resource_loaders = resource_loaders
        self.vr_codec = vr_codec or VRReferenceCodec()

    def get_supported_modes(self):
        res = super(ResourceHandler, self).get_supported_modes()
        res['modes'].append('resource')
        return res

    def _route_coll(self, params):
        """The collection name a request is bound to: the dynamic coll path
        param for auto collections, otherwise the route name itself."""
        coll = params.get('param.coll')
        if coll and coll != '*':
            return coll
        return params.get('_route', '').strip('/')

    @staticmethod
    def _acl_user(params):
        input_req = params.get('_input_req')
        if input_req:
            return input_req.env.get("HTTP_X_PYWB_ACL_USER")
        return None

    def __call__(self, params):
        if params.get('mode', 'resource') != 'resource':
            return super(ResourceHandler, self).__call__(params)

        # verifiable replay reference: replay exactly the records the token
        # is bound to, never fall back to another capture or the live web
        if params.get('vrref'):
            return self._serve_pinned(params)

        params.setdefault('_coll', self._route_coll(params))

        params['_closest_limit'] = self.CLOSEST_LIMIT

        cdx_iter, errs = self._load_index_source(params)
        if not cdx_iter:
            return None, None, errs

        last_exc = None

        for cdx in cdx_iter:
            if cdx.get('access', 'allow') != 'allow':
                raise AccessException(msg={'access': cdx['access'],
                                           'access_status': cdx.get('access_status', 451)},
                                      url=cdx['url'])

            for loader in self.resource_loaders:
                try:
                    out_headers, resp = loader(cdx, params)
                    if resp is not None:
                        return out_headers, resp, errs
                except (WbException, ArchiveLoadFailed) as e:
                    last_exc = e
                    if logger.isEnabledFor(logging.DEBUG):
                        traceback.print_exc()
                    errs[str(loader)] = str(e)

        if last_exc:
            errs['last_exc'] = last_exc

        return None, None, errs

    # ----- verifiable replay reference ------------------------------------
    def _serve_pinned(self, params):
        try:
            claims = self.vr_codec.decode(params.get('vrref'))
        except Exception as e:
            raise BadRequestException('Invalid verifiable replay reference: {0}'.format(e))

        coll = self._route_coll(params)
        if coll != claims['coll']:
            raise RecordUnavailableException(
                'Verifiable replay reference unavailable: it is bound to '
                'collection "{0}" and can not be replayed in "{1}"'.format(
                    claims['coll'], coll))

        # the loader path (eg. self-redirect checks) expects the selected url;
        # a pinned request only carries the token in the query string
        params['url'] = claims['url']
        params['matchType'] = 'exact'

        errs = {}

        header_cdx = self._find_pinned_row(params, claims['url'], claims['ts'],
                                           claims['h'], claims['digest'],
                                           errs, 'header record')

        payload_cdx = None
        if claims['p'] != claims['h']:
            payload_cdx = self._find_pinned_row(params,
                                                claims['p_url'],
                                                claims['p_ts'],
                                                claims['p'],
                                                claims['digest'],
                                                errs,
                                                'revisit donor record')

        for loader in self.resource_loaders:
            if not hasattr(loader, 'load_pinned'):
                # a verifiable reference always names a local capture:
                # live web / video loaders can not satisfy a pinned record
                continue
            try:
                out_headers, resp = loader.load_pinned(header_cdx,
                                                        payload_cdx,
                                                        claims,
                                                        params)
                if resp is not None:
                    return out_headers, resp, errs
            except RecordUnavailableException:
                raise
            except (WbException, ArchiveLoadFailed) as e:
                if logger.isEnabledFor(logging.DEBUG):
                    traceback.print_exc()
                raise RecordUnavailableException(
                    'Verifiable replay reference unavailable: {0}'.format(e))

        raise RecordUnavailableException(
            'Verifiable replay reference unavailable: no local archive '
            'loader for the bound record')

    def _find_pinned_row(self, params, url, ts, locator, digest, errs, label):
        """Find the single current index row for ``url`` at exactly ``ts``
        whose filename/offset/length equal the bound locator.

        Uses an exact query and never relies on candidate ordering: any
        number of same-second captures or added/reordered sources do not
        change which row is selected.  The row is still passed through the
        current access checker, so replay stays subject to current rules.
        """
        query_params = {'url': url,
                        'matchType': 'exact',
                        '_input_req': params.get('_input_req')}

        # carry routing params, eg. param.coll for auto collections, so the
        # lookup is scoped to the same collection as the pinned request
        for key, value in params.items():
            if key.startswith('param.'):
                query_params[key] = value

        try:
            cdx_iter, query_errs = self.index_source(query_params)
            if query_errs:
                errs.update(query_errs)
        except WbException as e:
            raise RecordUnavailableException(
                'Verifiable replay reference unavailable: index lookup for '
                'the {0} failed: {1}'.format(label, e))

        match = None
        for cdx in cdx_iter:
            if cdx.get('timestamp') != ts:
                continue
            if self._locator_matches(cdx, locator):
                match = cdx
                break

        if not match:
            raise RecordUnavailableException(
                'Verifiable replay reference unavailable: the {0} no '
                'longer matches this collection\'s index'.format(label))

        row_digest = normalize_digest(match.get('digest', ''))
        if digest and row_digest and row_digest != digest:
            raise RecordUnavailableException(
                'Verifiable replay reference unavailable: the {0} digest '
                'changed ({1} != {2})'.format(label, row_digest, digest))

        # current access rules still control every pinned replay: an
        # excluded capture is hidden exactly like in ordinary replay (the
        # bound row simply can not be selected), any other non-allow rule
        # (block, etc.) is reported with its access status
        if self.access_checker:
            allowed = list(self.access_checker.wrap_iter(iter([match]),
                                                         self._acl_user(params)))
            if not allowed:
                raise RecordUnavailableException(
                    'Verifiable replay reference unavailable: the {0} is '
                    'not accessible under the current access rules'.format(label))
            match = allowed[0]
            if match.get('access', 'allow') != 'allow':
                raise AccessException(msg={'access': match['access'],
                                           'access_status': match.get('access_status', 451)},
                                      url=url)

        return match

    @staticmethod
    def _locator_matches(cdx, locator):
        filename, offset, length = locator
        return (cdx.get('filename') == filename and
                str(cdx.get('offset')) == str(offset) and
                str(cdx.get('length', '-')) == str(length))


#=============================================================================
class DefaultResourceHandler(ResourceHandler):
    def __init__(self, index_source, warc_paths='', forward_proxy_prefix='',
                 use_local_file_load=False, vr_codec=None,
                 **kwargs):
        loaders = [WARCPathLoader(warc_paths, index_source, vr_codec=vr_codec),
                   LiveWebLoader(forward_proxy_prefix, use_local_file_load=use_local_file_load),
                   VideoLoader()
                  ]
        super(DefaultResourceHandler, self).__init__(index_source, loaders,
                                                     vr_codec=vr_codec, **kwargs)


#=============================================================================
class HandlerSeq(object):
    def __init__(self, handlers):
        self.handlers = handlers

    def get_supported_modes(self):
        if self.handlers:
            return self.handlers[0].get_supported_modes()
        else:
            return {}

    def __call__(self, params):
        all_errs = {}
        for handler in self.handlers:
            out_headers, res, errs = handler(params)
            all_errs.update(errs)
            if res is not None:
                return out_headers, res, all_errs

        return None, None, all_errs


