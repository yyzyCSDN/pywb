.. _recorder:

Recorder
========

The recorder component acts a proxy component, intercepting requests to and response from the :ref:`warcserver` and recording them
to a WARC file on disk.

The recorder uses the :class:`pywb.recorder.multifilewarcwriter.MultiFileWARCWriter` which extends the base :class:`warcio.warcwriter.WARCWriter` from :mod:`warcio` and provides support for:

* appending to multiple WARC files at once

* WARC 'rollover' based on maximum size idle time

* indexing (CDXJ) on write


Many of the features of the Recorder are created for use with Webrecorder project, although the core recorder is used to provide
a basic recording via ``/record/`` endpoint. (See: :ref:`recording-mode`)


Deduplication Filters
---------------------

The core recorder class provides for optional deduplication using the :class:`pywb.recorder.redisindexer.WritableRedisIndexer` class which requires Redis to store the index, and can be used to either:

* write duplicates responses.

* write ``revisit`` records.

* ignore duplicates and don't write to WARC.


Custom Filtering
----------------

The recorder filter system also includes a filtering system to allow for not writing certain requests and responses.
Filters include:

* Skipping by regex applied to source (``Warcserver-Source-Coll`` header from Warcserver)

* Skipping if ``Recorder-Skip: 1`` header is provided

* Skipping if ``Range`` request header is provided

* Filtering out certain HTTP headers, for example, http-only cookies

The additional recorder functionality will be enhanced in a future version.

For a more detailed examples, please consult the tests in :mod:`pywb.recorder.test.test_recorder`


JSON Response Body Redaction
----------------------------

The recorder can replace selected fields of JSON response bodies in the
archived copy only. The feature is **off by default** and is enabled with the
``json_redact`` recorder setting. The browser always keeps receiving the
untouched upstream response; redaction is applied solely to the data written
to the WARC.

Each rule specifies:

* ``url_filter``: a regular expression matched (``re.search``) against the
  response URL; the first matching rule applies

* ``pointers``: a list of ``RFC 6901`` JSON Pointer paths whose existing
  values are replaced, e.g. ``/user/email`` or ``/items/0/token``

* ``value``: the fixed replacement value (any JSON scalar/object); defaults
  to ``[REDACTED]``

Redaction is restricted to UTF-8 JSON resources: a media type of
``application/json`` or ``application/*+json`` (a missing charset defaults to
UTF-8) served with ``Content-Encoding`` ``identity`` (or absent) or ``gzip``.
Gzip entities are decompressed, redacted and deterministically re-compressed.
A capture whose URL matches a rule but whose response cannot be fully decoded
or parsed (for example invalid gzip data, malformed JSON, a non-UTF-8 charset
or an unsupported content encoding) is **not written to the archive at all**,
and the failure is reported on ``recorder.record_counts`` /
``recorder.redaction_failures`` (``reason`` included) so that an unprocessable
response can never leak the original payload into a WARC.

The persisted ``Content-Length`` (and ``Content-MD5`` when present), the WARC
payload/block digests, the dedup decision and the CDX entry are all computed
from the redacted entity. Repeated recordings therefore collapse into a
``revisit`` of the redacted payload, and changing a rule yields a new payload
digest and a new full capture that a revisit can never resolve against the
older payload.

Example configuration::

    recorder:
      source_coll: live
      json_redact:
        - url_filter: '^https?://api\.example\.com/v1/'
          pointers:
            - /password
            - /cards/0/number
          value: '[REDACTED]'
        - url_filter: '^https?://www\.example\.com/profile'
          pointers:
            - /email
          value: null



