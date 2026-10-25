"""JSON response body redaction for the recording pipeline.

A redaction policy is configured per recorder and is **off by default**.
Each rule binds:

* a ``url_filter`` regular expression defining the URL range the rule applies to
* a list of RFC 6901 ``JSON Pointer`` field paths
* a fixed ``value`` that every addressed field is replaced with

The policy only handles response payloads that are:

* ``UTF-8`` JSON (``application/json`` or ``application/*+json``; a missing
  charset defaults to UTF-8 per RFC 8259)
* served with ``Content-Encoding`` ``identity`` (or absent) or ``gzip``

The browser keeps receiving the untouched upstream response: redaction runs on
the separately buffered archive copy, after the response has been streamed to
the client. A capture that matches a rule but cannot be fully decoded, parsed
and re-serialized is never written to the archive, so an unprocessable
response can never leak the original payload into a WARC.
"""

import base64
import gzip
import hashlib
import json
import logging
import re

from io import BytesIO

from warcio.statusandheaders import StatusAndHeaders


logger = logging.getLogger(__name__)


# ============================================================================
class RedactionFailure(Exception):
    """Raised when a response matched a redaction rule but could not be
    fully redacted. The capture must not be archived.
    """

    def __init__(self, reason, url=None):
        self.reason = reason
        self.url = url
        msg = 'JSON redaction failed'
        if url:
            msg += ' for ' + url
        msg += ': ' + reason
        super(RedactionFailure, self).__init__(msg)


# ============================================================================
def parse_json_pointer(pointer):
    """Parse an RFC 6901 JSON Pointer string into a list of reference tokens.

    The empty string (whole document) yields an empty list.

    :param str pointer: the JSON Pointer, e.g. ``/user/email``
    :return: the list of decoded reference tokens
    :rtype: list[str]
    """
    if not isinstance(pointer, str):
        raise ValueError('JSON Pointer must be a string: {0!r}'.format(pointer))

    if pointer == '':
        return []

    if not pointer.startswith('/'):
        raise ValueError('Invalid JSON Pointer (must start with "/"): {0!r}'
                         .format(pointer))

    tokens = []
    for raw in pointer.split('/')[1:]:
        if '~' in raw:
            idx = 0
            while idx < len(raw):
                if raw[idx] == '~':
                    if idx + 1 >= len(raw) or raw[idx + 1] not in '01':
                        raise ValueError(
                            'Invalid JSON Pointer escape in {0!r}'.format(pointer))
                idx += 1
        tokens.append(raw.replace('~1', '/').replace('~0', '~'))

    return tokens


def _pointer_member(obj, token):
    """Resolve a single pointer token against a JSON container.

    :return: the contained value or ``_MISSING`` when the pointer does not
             resolve
    """
    if isinstance(obj, dict):
        return obj.get(token, _MISSING)

    if isinstance(obj, list):
        if token == '-':
            # refers to a new, non-existent element
            return _MISSING

        if not token or not token.isdigit():
            return _MISSING

        index = int(token)
        if index >= len(obj):
            return _MISSING

        return obj[index]

    return _MISSING


_MISSING = object()


def apply_json_pointers(obj, pointers, value):
    """Replace every existing member addressed by a pointer with ``value``.

    Missing pointers are ignored: the document is still considered processed
    successfully. The replacement happens in-place.

    :param obj: parsed JSON document
    :param list[list[str]] pointers: pre-parsed pointer token lists
    :param value: the fixed replacement value (a JSON-compatible object)
    """
    for tokens in pointers:
        if not tokens:
            # root pointer: replace the whole document
            return value

        current = obj
        resolved = True
        for token in tokens[:-1]:
            current = _pointer_member(current, token)
            if current is _MISSING:
                resolved = False
                break

        if not resolved:
            continue

        last = tokens[-1]

        if isinstance(current, dict):
            if last in current:
                current[last] = value
        elif isinstance(current, list):
            if last != '-' and last.isdigit() and int(last) < len(current):
                current[int(last)] = value

    return obj


# ============================================================================
class JsonRedactRule(object):
    """A single redaction rule: URL range + pointer paths + replacement value.
    """

    DEFAULT_VALUE = '[REDACTED]'

    def __init__(self, url_regex, pointers, value):
        self.url_regex = url_regex
        self.pointers = pointers
        self.value = value

    def matches(self, url):
        return bool(self.url_regex.search(url or ''))

    @classmethod
    def from_dict(cls, rule):
        if not isinstance(rule, dict):
            raise ValueError('Redaction rule must be a mapping, got: {0!r}'
                             .format(rule))

        url_filter = rule.get('url_filter') or rule.get('url')
        if not url_filter:
            raise ValueError('Redaction rule requires a "url_filter"')

        try:
            url_regex = re.compile(url_filter)
        except (re.error, TypeError) as e:
            raise ValueError('Invalid "url_filter" regex {0!r}: {1}'.format(
                url_filter, e))

        raw_pointers = rule.get('pointers') or rule.get('json_pointers') or []
        if isinstance(raw_pointers, str):
            raw_pointers = [raw_pointers]

        if not isinstance(raw_pointers, list):
            raise ValueError('"pointers" must be a list of JSON Pointer strings')

        pointers = [parse_json_pointer(p) for p in raw_pointers]

        value = rule.get('value', cls.DEFAULT_VALUE)

        return cls(url_regex, pointers, value)


# ============================================================================
class JsonRedactPolicy(object):
    """Holds the ordered list of redaction rules.

    The first rule whose ``url_filter`` matches a response URL wins.
    """

    # application/json and structured syntax suffix types such as
    # application/vnd.api+json
    JSON_TYPE_RE = re.compile(r'^application\/(?:[^/]+\+)?json$')

    SUPPORTED_ENCODINGS = ('identity', 'gzip', 'x-gzip')

    def __init__(self, rules=None):
        self.rules = rules or []

    @classmethod
    def from_config(cls, config):
        """Build a policy from recorder configuration.

        :param config: a rule mapping, a list of rule mappings, or ``None``
        :return: a :class:`JsonRedactPolicy` or ``None`` when redaction is
                 not configured (default off)
        """
        if not config:
            return None

        if isinstance(config, dict):
            config = [config]

        if not isinstance(config, list):
            raise ValueError('"json_redact" must be a rule or a list of rules')

        return cls([JsonRedactRule.from_dict(rule) for rule in config])

    def match(self, url):
        for rule in self.rules:
            if rule.matches(url):
                return rule

        return None

    # -- applicability checks ---------------------------------------------
    def _check_content_type(self, content_type):
        """Classify the response Content-Type.

        :return: ``True`` when it is in-scope UTF-8 JSON
        :return: ``False`` when it is not JSON at all (rule does not apply)
        :raises RedactionFailure: when it is JSON but the charset is not UTF-8
        """
        if not content_type:
            return False

        media_type, _, params = content_type.partition(';')
        media_type = media_type.strip().lower()

        if not self.JSON_TYPE_RE.match(media_type):
            return False

        charset = None
        for param in params.split(';'):
            name, sep, val = param.partition('=')
            if sep and name.strip().lower() == 'charset':
                charset = val.strip().strip('"\'').lower()

        if charset and charset not in ('utf-8', 'utf8'):
            raise RedactionFailure('unsupported_charset')

        return True

    def _content_encoding(self, http_headers):
        """Return the single accepted transfer content encoding.

        :raises RedactionFailure: for any encoding other than identity/gzip
        """
        encoding = http_headers.get_header('Content-Encoding')
        if not encoding:
            return 'identity'

        encodings = [part.strip().lower()
                     for part in encoding.split(',') if part.strip()]

        if len(encodings) != 1 or encodings[0] not in self.SUPPORTED_ENCODINGS:
            raise RedactionFailure('unsupported_content_encoding')

        if encodings[0] == 'identity':
            return 'identity'

        return 'gzip'

    # -- main entry point --------------------------------------------------
    def redact_response(self, record, builder):
        """Return a redacted copy of a WARC response record.

        :param record: the parsed WARC response record from the capture buffer
        :param builder: a warcio record builder (the WARC writer) used to
                        construct the replacement record
        :return: ``(record, applied)`` where ``applied`` is ``False`` when the
                 capture is out of scope and must be archived unchanged and
                 ``True`` when a redacted copy was produced
        :raises RedactionFailure: when the response matched a rule but could
                 not be decoded, parsed or re-serialized; the capture must
                 then be discarded
        """
        if record.rec_type != 'response' or not record.http_headers:
            return record, False

        url = record.rec_headers.get_header('WARC-Target-URI') or ''

        rule = self.match(url)
        if rule is None:
            return record, False

        try:
            return self._do_redact(record, builder, rule, url)
        except RedactionFailure as failure:
            failure.url = failure.url or url
            raise
        except Exception as e:
            logger.warning('unexpected redaction error for %s: %s', url, e)
            raise RedactionFailure('processing_error', url)

    def _do_redact(self, record, builder, rule, url):
        http_headers = record.http_headers

        is_json = self._check_content_type(
            http_headers.get_header('Content-Type'))

        if not is_json:
            # the rule only targets JSON payloads, other content types
            # (e.g. an HTML error page) are archived unchanged
            return record, False

        statuscode = http_headers.get_statuscode()
        if statuscode in ('204', '304') or statuscode.startswith('1'):
            return record, False

        encoding = self._content_encoding(http_headers)

        raw_payload = record.raw_stream.read()
        if not raw_payload:
            # HEAD / empty body: nothing sensitive to redact
            return record, False

        if encoding == 'gzip':
            try:
                payload = gzip.decompress(raw_payload)
            except Exception:
                raise RedactionFailure('invalid_gzip', url)
        else:
            payload = raw_payload

        try:
            text = payload.decode('utf-8')
        except UnicodeDecodeError:
            raise RedactionFailure('invalid_utf8', url)

        try:
            document = json.loads(text)
        except ValueError:
            raise RedactionFailure('invalid_json', url)

        document = apply_json_pointers(document, rule.pointers, rule.value)

        new_payload = json.dumps(document, ensure_ascii=False).encode('utf-8')

        if encoding == 'gzip':
            # mtime=0 keeps the entity byte-identical across repeated
            # recordings, which is required for digest-based deduplication
            new_payload = gzip.compress(new_payload, compresslevel=9, mtime=0)

        new_http_headers = self._rewrite_entity_headers(http_headers,
                                                        new_payload)

        new_warc_headers = self._copy_warc_headers(record.rec_headers)

        new_record = builder.create_warc_record(
            uri=url,
            record_type='response',
            payload=BytesIO(new_payload),
            length=len(new_payload),
            http_headers=new_http_headers,
            warc_headers=new_warc_headers)

        return new_record, True

    @staticmethod
    def _rewrite_entity_headers(http_headers, new_payload):
        """Clone the HTTP headers and make every entity-integrity header
        match the redacted entity.
        """
        new_headers = StatusAndHeaders(http_headers.statusline,
                                       list(http_headers.headers),
                                       protocol=http_headers.protocol)

        new_headers.replace_header('Content-Length', str(len(new_payload)))

        if new_headers.get_header('Content-MD5') is not None:
            digest = hashlib.md5(new_payload).digest()
            new_headers.replace_header('Content-MD5',
                                       base64.b64encode(digest).decode('ascii'))

        # the body reaching the recorder is already de-chunked, so persist it
        # as a fixed-length entity instead of keeping a stale chunked framing
        transfer_encoding = new_headers.get_header('Transfer-Encoding')
        if transfer_encoding:
            tokens = [part.strip().lower()
                      for part in transfer_encoding.split(',') if part.strip()]
            if tokens not in (['identity'], ['chunked']):
                raise RedactionFailure('unsupported_transfer_encoding')
            new_headers.remove_header('Transfer-Encoding')

        return new_headers

    @staticmethod
    def _copy_warc_headers(rec_headers):
        """Copy WARC headers, dropping headers that describe the old entity
        and must be recomputed for the redacted record.
        """
        skip = ('content-length', 'warc-block-digest', 'warc-payload-digest')
        headers = [(name, value) for name, value in rec_headers.headers
                   if name.lower() not in skip]

        return StatusAndHeaders(rec_headers.statusline, headers,
                                protocol=rec_headers.protocol)
