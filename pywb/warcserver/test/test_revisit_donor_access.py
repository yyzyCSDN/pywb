"""
Controlled-archive tests for the opt-in revisit payload donor
authorization policy (``revisit_donor_access``).

When the policy is disabled, only the requested capture is authorized, as
before. When enabled, the donor capture that actually provides the payload
of a revisit is checked against the access rules and embargo for the
current trusted ACL user, using the donor's own url, capture time and
owning collection - both when the donor is located directly through the
``orig.*`` cdx fields and when it is re-queried from the revisit
reference information (WARC-Refers-To-*).
"""
from gevent import monkey; monkey.patch_all()

import base64
import hashlib
import os
from io import BytesIO

import pytest
import webtest
from warcio.statusandheaders import StatusAndHeadersParser
from warcio.bufferedreaders import ChunkedDataReader
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders

from pywb.utils.canonicalize import canonicalize
from pywb.warcserver.access_checker import AccessChecker
from pywb.warcserver.basewarcserver import BaseWarcServer
from pywb.warcserver.handlers import DefaultResourceHandler
from pywb.warcserver.index.aggregator import SimpleAggregator
from pywb.warcserver.index.indexsource import FileIndexSource

from .testutils import BaseTestClass, TempDirTests


BODY = b'DONOR-PAYLOAD-DATA-v1'
BODY_DIGEST = base64.b32encode(hashlib.sha1(BODY).digest()).decode().rstrip('=')
EMPTY_DIGEST = '3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ'

# a different, directly playable capture of the revisit-a url
OTHER_BODY = b'OTHER-REQUESTED-CAPTURE'
OTHER_DIGEST = base64.b32encode(hashlib.sha1(OTHER_BODY).digest()).decode().rstrip('=')

DONOR_URL = 'http://staffonly.example.com/data'
DONOR_TS = '20200101000000'
DONOR_DATE = '2020-01-01T00:00:00Z'

DUPE_URL = 'http://dupe.example.com/item'
DUPE_NEW_TS = '20200601000000'
DUPE_NEW_DATE = '2020-06-01T00:00:00Z'
DUPE_OLD_TS = '20190101000000'
DUPE_OLD_DATE = '2019-01-01T00:00:00Z'

REVISIT_A_URL = 'http://revisit-a.example.com/page'
REVISIT_A_TS = '20200505000000'
REVISIT_A_DATE = '2020-05-05T00:00:00Z'

# an earlier, non-revisit capture of the same requested url
OTHER_TS = '20200404000000'
OTHER_DATE = '2020-04-04T00:00:00Z'

REVISIT_B_URL = 'http://revisit-b.example.com/page'
REVISIT_B_TS = '20200506000000'

REVISIT_C_URL = 'http://revisit-c.example.com/page'
REVISIT_C_TS = '20200507000000'

REVISIT_EMPTY_URL = 'http://revisit-empty.example.com/page'
REVISIT_EMPTY_TS = '20200508000000'

REVISIT_REDIR_URL = 'http://revisit-redir.example.com/'
REVISIT_REDIR_TS = '20200509000000'

STAFF_HEADERS = {'X-Pywb-ACL-User': 'staff'}

# default rules: staffonly donor allowed for "staff" only and blocked
# otherwise; of the two copies of the dupe donor the newest one (closest to
# the revisit reference) is blocked for anonymous users but allowed for
# staff, the older copy is allowed by default.
# the surt keys keep the subdomains, as produced by canonicalize()
STAFF_SURT = 'com,example,staffonly)/data'
DUPE_SURT = 'com,example,dupe)/item'

ACL_RULES = """\
{staff_surt} - {{"access": "block", "url": "{staff}"}}
{staff_surt} - {{"access": "allow", "user": "staff", "url": "{staff}"}}
{dupe_surt} - {{"access": "allow", "user": "staff", "after": "20200301000000", "url": "{dupe}"}}
{dupe_surt} - {{"access": "block", "after": "20200301000000", "url": "{dupe}"}}
""".format(staff_surt=STAFF_SURT, staff=DONOR_URL,
           dupe_surt=DUPE_SURT, dupe=DUPE_URL)

ACL_RULES_ALLOW_ALL = """\
{staff_surt} - {{"access": "allow", "url": "{staff}"}}
""".format(staff_surt=STAFF_SURT, staff=DONOR_URL)

ACL_RULES_BLOCK_ALL = """\
{staff_surt} - {{"access": "block", "url": "{staff}"}}
""".format(staff_surt=STAFF_SURT, staff=DONOR_URL)

# the donor is excluded entirely, as if it did not exist
ACL_RULES_EXCLUDE = """\
{staff_surt} - {{"access": "exclude", "url": "{staff}"}}
""".format(staff_surt=STAFF_SURT, staff=DONOR_URL)


def surt(url):
    return canonicalize(url)


def http_headers(status='200 OK', extra=None):
    headers = [('Content-Type', 'text/html')]
    if extra:
        headers += extra
    return StatusAndHeaders(status, headers, protocol='HTTP/1.1')


# ============================================================================
class TestRevisitDonorAccess(TempDirTests, BaseTestClass):
    @classmethod
    def setup_class(cls):
        super(TestRevisitDonorAccess, cls).setup_class()

        cls.warc_dir = os.path.join(cls.root_dir, 'warcs')
        os.mkdir(cls.warc_dir)

        cls.donors_warc = os.path.join(cls.warc_dir, 'donors.warc.gz')
        cls.revisits_warc = os.path.join(cls.warc_dir, 'revisits.warc.gz')

        locs = {}
        cls._write_donors(locs)
        cls._write_revisits(locs)

        cls.acl_file = os.path.join(cls.root_dir, 'rules.aclj')
        with open(cls.acl_file, 'w') as fh:
            fh.write(ACL_RULES)

        cls.acl_exclude_file = os.path.join(cls.root_dir, 'exclude.aclj')
        with open(cls.acl_exclude_file, 'w') as fh:
            fh.write(ACL_RULES_EXCLUDE)

        index_file = os.path.join(cls.root_dir, 'index.cdx')
        with open(index_file, 'w') as fh:
            fh.write(cls._build_cdx(locs))

        source = SimpleAggregator(
            {'controlled': FileIndexSource(index_file)})

        def make_route(name, policy_on, acl_file=None, embargo=None):
            access_checker = AccessChecker(
                acl_file or cls.acl_file,
                default_access='allow',
                embargo=embargo,
                revisit_donor_access=policy_on)

            handler = DefaultResourceHandler(
                source,
                cls.warc_dir + os.path.sep,
                access_checker=access_checker)

            app.add_route('/' + name, handler)

        app = BaseWarcServer()
        make_route('on', True)
        make_route('off', False)
        make_route('embargo', True, embargo={'after': '20190601000000'})
        make_route('excluded', True, acl_file=cls.acl_exclude_file)

        cls.testapp = webtest.TestApp(app)

    # ------------------------------------------------------------------
    # archive construction
    # ------------------------------------------------------------------
    @classmethod
    def _write_response(cls, writer, fh, url, date, body=BODY,
                        status='200 OK'):
        length = len(body)
        headers = http_headers(status, [('Content-Length', str(length))])
        rec = writer.create_warc_record(
            url, 'response',
            payload=BytesIO(body),
            http_headers=headers)
        rec.rec_headers.replace_header('WARC-Date', date)

        offset = fh.tell()
        writer.write_record(rec)
        return offset, fh.tell() - offset

    @classmethod
    def _write_revisit(cls, writer, fh, url, date, ref_url, ref_date,
                       digest=BODY_DIGEST, status='200 OK', extra_headers=None):
        headers = http_headers(status, extra_headers)
        rec = writer.create_revisit_record(
            url, 'sha1:' + digest, ref_url, ref_date,
            http_headers=headers)
        rec.rec_headers.replace_header('WARC-Date', date)

        offset = fh.tell()
        writer.write_record(rec)
        return offset, fh.tell() - offset

    @classmethod
    def _write_donors(cls, locs):
        with open(cls.donors_warc, 'wb') as fh:
            writer = WARCWriter(fh, gzip=True)

            locs['donor'] = cls._write_response(
                writer, fh, DONOR_URL, DONOR_DATE)

            locs['dupe_new'] = cls._write_response(
                writer, fh, DUPE_URL, DUPE_NEW_DATE)

            locs['dupe_old'] = cls._write_response(
                writer, fh, DUPE_URL, DUPE_OLD_DATE)

            # earlier non-revisit capture of the revisit-a requested url
            locs['other_capture'] = cls._write_response(
                writer, fh, REVISIT_A_URL, OTHER_DATE, body=OTHER_BODY)

    @classmethod
    def _write_revisits(cls, locs):
        with open(cls.revisits_warc, 'wb') as fh:
            writer = WARCWriter(fh, gzip=True)

            locs['revisit_a'] = cls._write_revisit(
                writer, fh, REVISIT_A_URL, REVISIT_A_DATE,
                DONOR_URL, DONOR_DATE)

            locs['revisit_b'] = cls._write_revisit(
                writer, fh, REVISIT_B_URL, '2020-05-06T00:00:00Z',
                DUPE_URL, DUPE_NEW_DATE)

            locs['revisit_c'] = cls._write_revisit(
                writer, fh, REVISIT_C_URL, '2020-05-07T00:00:00Z',
                DONOR_URL, DONOR_DATE)

            locs['revisit_empty'] = cls._write_revisit(
                writer, fh, REVISIT_EMPTY_URL, '2020-05-08T00:00:00Z',
                DONOR_URL, DONOR_DATE, digest=EMPTY_DIGEST)

            locs['revisit_redir'] = cls._write_revisit(
                writer, fh, REVISIT_REDIR_URL, '2020-05-09T00:00:00Z',
                DONOR_URL, DONOR_DATE,
                status='302 Found',
                extra_headers=[('Location', 'http://example.com/other')])

    @classmethod
    def _build_cdx(cls, locs):
        donors = 'donors.warc.gz'
        revisits = 'revisits.warc.gz'

        def line(key, ts, url, mime, status, digest, loc, filename,
                 orig=None):
            offset, length = loc
            # CDX11: key ts url mime status digest redirect robotflags
            # length offset filename
            parts = [key, ts, url, mime, status, digest, '-', '-',
                     str(length), str(offset), filename]
            if orig:
                o_offset, o_length = orig
                parts += [str(o_length), str(o_offset),
                          'donors.warc.gz']
            return ' '.join(parts) + '\n'

        entries = []

        def add(key, ts, url, mime, status, digest, loc, filename,
                orig=None):
            entries.append(line(key, ts, url, mime, status, digest,
                                loc, filename, orig=orig))

        add(surt(DONOR_URL), DONOR_TS, DONOR_URL,
            'text/html', '200', BODY_DIGEST, locs['donor'], donors)
        add(surt(DUPE_URL), DUPE_OLD_TS, DUPE_URL,
            'text/html', '200', BODY_DIGEST, locs['dupe_old'], donors)
        add(surt(DUPE_URL), DUPE_NEW_TS, DUPE_URL,
            'text/html', '200', BODY_DIGEST, locs['dupe_new'], donors)

        # earlier non-revisit capture of the same requested url, which must
        # not be served as a replacement when the revisit donor is denied
        add(surt(REVISIT_A_URL), OTHER_TS, REVISIT_A_URL,
            'text/html', '200', OTHER_DIGEST,
            locs['other_capture'], donors)

        # case 1: donor re-queried from the revisit reference information
        add(surt(REVISIT_A_URL), REVISIT_A_TS, REVISIT_A_URL,
            'warc/revisit', '200', BODY_DIGEST,
            locs['revisit_a'], revisits)
        add(surt(REVISIT_B_URL), REVISIT_B_TS, REVISIT_B_URL,
            'warc/revisit', '200', BODY_DIGEST,
            locs['revisit_b'], revisits)

        # case 3: donor located directly through orig.* fields
        add(surt(REVISIT_C_URL), REVISIT_C_TS, REVISIT_C_URL,
            'text/html', '200', BODY_DIGEST,
            locs['revisit_c'], revisits, orig=locs['donor'])

        # empty entity and redirect revisits borrow no usable external payload
        add(surt(REVISIT_EMPTY_URL), REVISIT_EMPTY_TS,
            REVISIT_EMPTY_URL, 'warc/revisit', '200', EMPTY_DIGEST,
            locs['revisit_empty'], revisits)
        add(surt(REVISIT_REDIR_URL), REVISIT_REDIR_TS,
            REVISIT_REDIR_URL, 'warc/revisit', '302', BODY_DIGEST,
            locs['revisit_redir'], revisits)

        # local index sources require cdx sorted by (urlkey, timestamp)
        entries.sort(key=lambda text: (text.split(' ', 2)[0],
                                       text.split(' ', 2)[1]))
        return ''.join(entries)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def resource(self, route, url, ts, headers=None, status=None):
        path = '/{route}/resource?url={url}&closest={ts}'.format(
            route=route, url=url, ts=ts)
        return self.testapp.get(path, headers=headers, status=status)

    @staticmethod
    def warc_headers(resp):
        buff = BytesIO(resp.body)
        buff = ChunkedDataReader(buff)
        return StatusAndHeadersParser(['WARC/1.0']).parse(buff), buff

    # ------------------------------------------------------------------
    # policy disabled: existing behavior, only the requested capture
    # is authorized (the requested revisit url has no blocking rule)
    # ------------------------------------------------------------------
    def test_policy_off_donor_blocked_still_replays(self):
        resp = self.resource('off', REVISIT_A_URL, REVISIT_A_TS, status=200)
        assert BODY in resp.body

    def test_policy_off_orig_donor_blocked_still_replays(self):
        resp = self.resource('off', REVISIT_C_URL, REVISIT_C_TS, status=200)
        assert BODY in resp.body

    # ------------------------------------------------------------------
    # policy on: reference-re-queried donor path (case 1)
    # ------------------------------------------------------------------
    def test_donor_blocked_anonymous_refused(self):
        resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS, status=451)
        # explicit refusal, no live web fallback, no other capture
        assert resp.json == {'access': 'block', 'access_status': 451}

    def test_blocked_donor_does_not_switch_requested_capture(self):
        # another, directly playable capture exists for the same url, but a
        # donor denial must end the replay instead of switching to it
        resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS, status=451)
        assert resp.json == {'access': 'block', 'access_status': 451}
        assert OTHER_BODY not in resp.body

    def test_donor_allowed_for_staff(self):
        resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS,
                             headers=STAFF_HEADERS, status=200)
        assert BODY in resp.body

    def test_authorization_not_reused_across_users(self):
        # staff allowed first
        resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS,
                             headers=STAFF_HEADERS, status=200)
        assert BODY in resp.body

        # anonymous request afterwards must still be refused
        resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS, status=451)
        assert resp.json == {'access': 'block', 'access_status': 451}

        # and staff is still allowed
        resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS,
                             headers=STAFF_HEADERS, status=200)
        assert BODY in resp.body

    def test_alternate_allowed_donor_copy_used(self):
        # the closest (2020-06-01) copy is blocked for anonymous users and
        # must not provide the payload; the older allowed copy (2019-01-01)
        # matches the same reference and digest and is used instead
        resp = self.resource('on', REVISIT_B_URL, REVISIT_B_TS, status=200)
        assert BODY in resp.body

        headers, _ = self.warc_headers(resp)
        assert headers.get_header('WARC-Refers-To-Target-URI') == DUPE_URL
        assert headers.get_header('WARC-Refers-To-Date') == DUPE_OLD_DATE

    def test_alternate_donor_staff_uses_closest_copy(self):
        # staff may use the closest copy that is blocked for anonymous users
        resp = self.resource('on', REVISIT_B_URL, REVISIT_B_TS,
                             headers=STAFF_HEADERS, status=200)
        headers, _ = self.warc_headers(resp)
        assert headers.get_header('WARC-Refers-To-Date') == DUPE_NEW_DATE

    # ------------------------------------------------------------------
    # policy on: direct orig.* donor path (case 3)
    # ------------------------------------------------------------------
    def test_orig_donor_blocked_anonymous_refused(self):
        resp = self.resource('on', REVISIT_C_URL, REVISIT_C_TS, status=451)
        assert resp.json == {'access': 'block', 'access_status': 451}

    def test_orig_donor_allowed_for_staff(self):
        resp = self.resource('on', REVISIT_C_URL, REVISIT_C_TS,
                             headers=STAFF_HEADERS, status=200)
        assert BODY in resp.body

    # ------------------------------------------------------------------
    # empty entity and redirect revisits keep their usual handling
    # ------------------------------------------------------------------
    def test_empty_revisit_needs_no_donor(self):
        resp = self.resource('on', REVISIT_EMPTY_URL, REVISIT_EMPTY_TS,
                             status=200)
        assert BODY not in resp.body

    def test_redirect_revisit_needs_no_donor(self):
        resp = self.resource('on', REVISIT_REDIR_URL, REVISIT_REDIR_TS,
                             status=200)
        assert b'302 Found' in resp.body
        assert BODY not in resp.body

    # ------------------------------------------------------------------
    # excluded donors behave as if they do not exist: 404, never a body
    # ------------------------------------------------------------------
    def test_excluded_donor_refused_reference_path(self):
        resp = self.resource('excluded', REVISIT_A_URL, REVISIT_A_TS,
                             status=404)
        assert BODY not in resp.body
        assert OTHER_BODY not in resp.body

    def test_excluded_donor_refused_orig_path(self):
        resp = self.resource('excluded', REVISIT_C_URL, REVISIT_C_TS,
                             status=404)
        assert BODY not in resp.body

    # ------------------------------------------------------------------
    # embargo applies to the donor as well
    # ------------------------------------------------------------------
    def test_embargoed_donor_refused(self):
        # donor captured 2020-01-01 is under the "after 2019-06-01" embargo
        # (default exclude), so no allowed donor exists -> 404, no replay
        resp = self.resource('embargo', REVISIT_A_URL, REVISIT_A_TS,
                             status=404)
        assert BODY not in resp.body

    # ------------------------------------------------------------------
    # rule changes take effect immediately, no cached allow is reused
    # ------------------------------------------------------------------
    def test_rule_change_invalidates_cached_authorization(self):
        # blocked for anonymous under the original rules
        self.resource('on', REVISIT_A_URL, REVISIT_A_TS, status=451)

        with open(self.acl_file, 'w') as fh:
            fh.write(ACL_RULES_ALLOW_ALL)

        try:
            # the new rules allow the donor, replay works without restart
            resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS,
                                 status=200)
            assert BODY in resp.body

            with open(self.acl_file, 'w') as fh:
                fh.write(ACL_RULES_BLOCK_ALL)

            # staff is not exempt anymore either, the cached "allow" from
            # the previous rules must not keep granting access
            resp = self.resource('on', REVISIT_A_URL, REVISIT_A_TS,
                                 headers=STAFF_HEADERS, status=451)
            assert resp.json == {'access': 'block', 'access_status': 451}
        finally:
            with open(self.acl_file, 'w') as fh:
                fh.write(ACL_RULES)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
