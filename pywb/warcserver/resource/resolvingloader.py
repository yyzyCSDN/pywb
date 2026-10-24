import six
from warcio.recordloader import ArchiveLoadFailed
from warcio.timeutils import iso_date_to_timestamp

from pywb.utils.io import no_except_close
from pywb.utils.wbexception import AccessException, NotFoundException
from pywb.warcserver.resource.blockrecordloader import BlockArcWarcRecordLoader


# =================================================================
class RevisitDonorAccessException(AccessException):
    """Raised when the revisit donor authorization policy is enabled and the
    capture that provides the payload of a revisit record is blocked for the
    current user.

    Unlike ordinary loading failures, this must end the replay: the resource
    must not be fetched from the live web and another requested capture must
    not be tried instead.
    """


# =================================================================
class RevisitDonorNotFoundException(NotFoundException):
    """Raised when the revisit donor authorization policy is enabled and no
    allowed donor copy matching the revisit reference and digest exists
    (all candidates are excluded or missing). The replay is refused instead of
    falling back to the live web or another requested capture.
    """


# =================================================================
class ResolvingLoader(object):
    MISSING_REVISIT_MSG = 'Original for revisit record could not be loaded'

    EMPTY_DIGEST = '3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ'

    def __init__(self, path_resolvers, record_loader=None, no_record_parse=False,
                 access_checker=None):
        self.path_resolvers = path_resolvers
        self.record_loader = record_loader if record_loader is not None else BlockArcWarcRecordLoader()
        self.no_record_parse = no_record_parse
        self.access_checker = access_checker

    def donor_access_enabled(self):
        """The revisit donor authorization policy is opt-in and is only
        available when an access checker exists for the collection."""
        return (self.access_checker is not None and
                getattr(self.access_checker, 'revisit_donor_access', False))

    def __call__(self, cdx, failed_files, cdx_loader, *args, **kwargs):
        acl_user = kwargs.get('acl_user')
        headers_record, payload_record = self.load_headers_and_payload(cdx,
                                                                        failed_files,
                                                                        cdx_loader,
                                                                        acl_user)

        # Default handling logic when loading http status/headers

        # special case: set header to payload if old-style revisit
        # with missing header
        if not headers_record:
            headers_record = payload_record
        elif headers_record != payload_record:
            # close remainder of stream as this record only used for
            # (already parsed) headers
            no_except_close(headers_record.raw_stream)

            # special case: check if headers record is actually empty
            # (eg empty revisit), then use headers from revisit
            if not headers_record.http_headers.headers:
                headers_record = payload_record

        if not headers_record or not payload_record:
            if headers_record:
                no_except_close(headers_record.raw_stream)
            if payload_record:
                no_except_close(payload_record.raw_stream)
            raise ArchiveLoadFailed('Could not load ' + str(cdx))

        # ensure status line is valid from here
        headers_record.http_headers.validate_statusline('204 No Content')

        return (headers_record.http_headers, payload_record.raw_stream)

    def load_headers_and_payload(self, cdx, failed_files, cdx_loader,
                                 acl_user=None):
        """
        Resolve headers and payload for a given capture
        In the simple case, headers and payload are in the same record.
        In the case of revisit records, the payload and headers may be in
        different records.

        If the original has already been found, lookup original using
        orig. fields in cdx dict.
        Otherwise, call _load_different_url_payload() to get cdx index
        from a different url to find the original record.

        When the revisit donor authorization policy is enabled, the donor
        capture is checked against the access rules and embargo for
        ``acl_user`` in both revisit resolution paths below.
        """
        has_curr = (cdx['filename'] != '-')
        # has_orig = (cdx.get('orig.filename', '-') != '-')
        orig_f = cdx.get('orig.filename')
        has_orig = orig_f and orig_f != '-'

        # load headers record from cdx['filename'] unless it is '-' (rare)
        headers_record = None
        payload_record = None
        if has_curr:
            headers_record = self._resolve_path_load(cdx, False, failed_files)

        # two index lookups
        # Case 1: if mimetype is still warc/revisit
        if cdx.get('mime') == 'warc/revisit' and headers_record:
            if headers_record.http_headers:
                status = headers_record.http_headers.get_statuscode()
                # optimization: if redirect, don't load payload record, as it'll be ignored by browser
                # always replay zero-length payload
                # redirects need no external payload, so no donor access check
                if status and status.startswith('3'):
                    headers_record.http_headers.replace_header('Content-Length', '0')
                    return headers_record, headers_record

            payload_record = self._load_different_url_payload(cdx,
                                                              headers_record,
                                                              failed_files,
                                                              cdx_loader,
                                                              acl_user)

        # single lookup cases
        # case 2: non-revisit
        elif (has_curr and not has_orig):
            payload_record = headers_record

        # case 3: identical url revisit, load payload from orig.filename
        elif (has_orig):
            payload_record = self._resolve_path_load(cdx, True, failed_files)
            self._check_orig_donor_access(cdx, headers_record,
                                          payload_record, acl_user)

        return headers_record, payload_record

    def _check_orig_donor_access(self, cdx, headers_record,
                                 payload_record, acl_user):
        """Apply the donor policy to a donor located directly through the
        ``orig.filename``/``orig.offset``/``orig.length`` cdx fields.

        The actually loaded donor record is checked using its own original
        URL and capture time (falling back to the revisit reference and then
        to the requested capture identity) and the collection owning the
        requested capture.
        """
        if not self.donor_access_enabled():
            return

        # an empty payload borrows no external content, keep usual handling
        if cdx.get('digest') == self.EMPTY_DIGEST:
            return

        donor_url, donor_ts = self._get_donor_identity(cdx,
                                                        headers_record,
                                                        payload_record)

        access = self.access_checker.get_access(donor_url,
                                                donor_ts,
                                                None,
                                                cdx.get('source-coll'),
                                                acl_user)

        if access == 'allow':
            return

        no_except_close(payload_record.raw_stream)
        if (headers_record is not None and
                headers_record is not payload_record):
            no_except_close(headers_record.raw_stream)

        if access is None:
            raise RevisitDonorNotFoundException(
                self.MISSING_REVISIT_MSG, url=donor_url)

        raise RevisitDonorAccessException(
            msg={'access': access, 'access_status': 451},
            url=donor_url)

    def _get_donor_identity(self, cdx, headers_record, payload_record):
        """Return the (url, timestamp) identifying the donor capture whose
        payload was actually loaded."""
        donor_url = None
        donor_ts = None

        rec_headers = getattr(payload_record, 'rec_headers', None)
        if rec_headers is not None:
            donor_url = rec_headers.get_header('WARC-Target-URI')
            donor_date = rec_headers.get_header('WARC-Date')
            if donor_date:
                donor_ts = iso_date_to_timestamp(donor_date)

        # fall back to the revisit reference information
        if not donor_url and (headers_record is not None and
                              headers_record is not payload_record):
            donor_url = headers_record.rec_headers.get_header(
                'WARC-Refers-To-Target-URI')
            donor_date = headers_record.rec_headers.get_header(
                'WARC-Refers-To-Date')
            if donor_date:
                donor_ts = iso_date_to_timestamp(donor_date)

        # last resort: the requested capture's identity
        if not donor_url:
            donor_url = cdx.get('url')
        if not donor_ts:
            donor_ts = cdx.get('timestamp')

        return donor_url, donor_ts

    def _resolve_path_load(self, cdx, is_original, failed_files):
        """
        Load specific record based on filename, offset and length
        fields in the cdx.
        If original=True, use the orig.* fields for the cdx

        Resolve the filename to full path using specified path resolvers

        If failed_files list provided, keep track of failed resolve attempts
        """

        if is_original:
            (filename, offset, length) = (cdx['orig.filename'],
                                          cdx['orig.offset'],
                                          cdx['orig.length'])
        else:
            (filename, offset, length) = (cdx['filename'],
                                          cdx['offset'],
                                          cdx.get('length', '-'))

        # optimization: if same file already failed this request,
        # don't try again
        if failed_files is not None and filename in failed_files:
            raise ArchiveLoadFailed('Skipping Already Failed: ' + filename)

        any_found = False
        last_exc = None
        last_traceback = None
        for resolver in self.path_resolvers:
            possible_paths = resolver(filename, cdx)

            if not possible_paths:
                continue

            if isinstance(possible_paths, six.string_types):
                possible_paths = [possible_paths]

            for path in possible_paths:
                any_found = True
                try:
                    return (self.record_loader.
                            load(path, offset, length,
                                 no_record_parse=self.no_record_parse))

                except Exception as ue:
                    last_exc = ue
                    import sys
                    last_traceback = sys.exc_info()[2]

        # Unsuccessful if reached here
        if failed_files is not None:
            failed_files.append(filename)

        if last_exc:
            # msg = str(last_exc.__class__.__name__)
            msg = str(last_exc)
        else:
            msg = 'Archive File Not Found'

        # raise ArchiveLoadFailed(msg, filename), None, last_traceback
        six.reraise(ArchiveLoadFailed, ArchiveLoadFailed(filename + ': ' + msg), last_traceback)

    def _load_different_url_payload(self, cdx, headers_record,
                                    failed_files, cdx_loader, acl_user=None):
        """
        Handle the case where a duplicate of a capture with same digest
        exists at a different url.

        If a cdx_server is provided, a query is made for matching
        url, timestamp and digest.

        When the revisit donor authorization policy is enabled, each donor
        candidate matching the reference and digest is checked against the
        access rules and embargo for the current user before its payload is
        loaded. A disallowed donor never provides the payload; further
        allowed copies are tried instead. If no allowed copy can serve the
        payload, the replay is refused explicitly rather than falling back
        to the live web.

        Raise exception if no matches found.
        """

        check_donor = self.donor_access_enabled()

        digest = cdx.get('digest', '-')

        # if the digest is the empty record digest, don't attempt to look up the payload record!
        # the payload is simply empty, so use empty payload of existing record
        # no external payload is borrowed, so no donor access check
        if digest == self.EMPTY_DIGEST:
            return headers_record

        ref_target_uri = (headers_record.rec_headers.
                          get_header('WARC-Refers-To-Target-URI'))

        target_uri = headers_record.rec_headers.get_header('WARC-Target-URI')

        # if no target uri, no way to find the original
        if not ref_target_uri:
            raise ArchiveLoadFailed(self.MISSING_REVISIT_MSG)

        ref_target_date = (headers_record.rec_headers.
                           get_header('WARC-Refers-To-Date'))

        if not ref_target_date:
            ref_target_date = cdx['timestamp']
        else:
            ref_target_date = iso_date_to_timestamp(ref_target_date)

        try:
            orig_cdx_lines = self.load_cdx_for_dupe(ref_target_uri,
                                                    ref_target_date,
                                                    digest,
                                                    cdx_loader)
        except NotFoundException:
            if check_donor:
                raise RevisitDonorNotFoundException(self.MISSING_REVISIT_MSG,
                                                    url=ref_target_uri)
            raise ArchiveLoadFailed(self.MISSING_REVISIT_MSG)

        blocked_access = None

        for orig_cdx in orig_cdx_lines:
            if check_donor:
                # the decision is evaluated for this user and the current
                # rules on every candidate; it is never cached or reused
                access = self.access_checker.check_donor_access(orig_cdx,
                                                                acl_user)
                if access is None:
                    # excluded donor: treated as if it does not exist
                    continue

                if access != 'allow':
                    # blocked donor may not provide the payload, but another
                    # allowed copy matching reference and digest may exist
                    blocked_access = access
                    continue

            try:
                payload_record = self._resolve_path_load(orig_cdx, False,
                                                         failed_files)
                return payload_record

            except ArchiveLoadFailed as e:
                pass

        if check_donor:
            # no allowed donor copy: refuse the replay explicitly, never
            # fall back to the live web nor switch to another requested
            # capture
            if blocked_access is not None:
                raise RevisitDonorAccessException(
                    msg={'access': blocked_access, 'access_status': 451},
                    url=ref_target_uri)

            raise RevisitDonorNotFoundException(self.MISSING_REVISIT_MSG,
                                                url=ref_target_uri)

        raise ArchiveLoadFailed(self.MISSING_REVISIT_MSG)

    def load_cdx_for_dupe(self, url, timestamp, digest, cdx_loader):
        """
        If a cdx_server is available, return response from server,
        otherwise empty list
        """
        if not cdx_loader:
            return iter([])

        filters = []

        filters.append('!mime:warc/revisit')

        if digest and digest != '-':
            filters.append('digest:' + digest)

        params = dict(url=url,
                      closest=timestamp,
                      filter=filters)

        return cdx_loader(params)
