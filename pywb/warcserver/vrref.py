"""
Verifiable replay references (VRR) for a single captured HTTP resource.

A verifiable replay reference is an opaque, HMAC signed token which is bound
to exactly one local capture at the time it is minted:

* the collection it was minted from (the token can not be replayed in a
  different collection),
* the concrete "header record" (WARC/ARC filename, offset and length of the
  capture that carries the HTTP status line and headers -- the revisit record
  itself for a revisit),
* the concrete "payload record" (the record that carries the entity bytes;
  for a revisit this is the resolved donor record, for a regular response it
  is the same record as the header record),
* the payload content fingerprint (digest) as recorded in the index.

The token never carries a file system path: the filename stored in it is only
ever compared against an entry of the *current* index of the bound
collection and then resolved through that collection's regular path
resolvers.  A token therefore can not be used to point the loader at an
arbitrary file.

The token format is::

    vr1.<base64url(json claims)>.<base64url(hmac-sha256(secret, msg))>

The claims JSON intentionally uses short keys to keep the token compact.
"""

import base64
import hashlib
import hmac
import json
import os
import re

import six


# replay modifier used in archival URLs: /<coll>/vr_/urn:vr:<token>
VR_MOD = 'vr_'

# the token is carried in a URN so that WbUrl parsing does not prepend a
# scheme to it
VR_URN_PREFIX = 'urn:vr:'

VERSION = 'vr1'

TS_RE = re.compile(r'^\d{14}$')

# names of the JSON claim fields
CLAIM_VERSION = 'v'
CLAIM_COLL = 'c'
CLAIM_TS = 't'
CLAIM_URL = 'u'
CLAIM_DIGEST = 'g'
CLAIM_REC_TYPE = 'r'
CLAIM_HEADER = 'h'
CLAIM_PAYLOAD = 'p'


# =============================================================================
def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(value):
    if isinstance(value, six.text_type):
        value = value.encode('ascii')
    padding = b'=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def normalize_digest(digest):
    """Return the digest in the canonical form used in a token.

    CDX digests are upper case base32, optionally prefixed with the
    algorithm (``sha1:``).  The prefix is kept so that other digest
    algorithms can be distinguished.
    """
    if not digest or digest == '-':
        return ''
    digest = digest.strip()
    if ':' in digest:
        algo, value = digest.split(':', 1)
        digest = algo.lower() + ':' + value.upper()
    else:
        digest = digest.upper()
    return digest


def digest_algorithm(digest):
    if ':' in digest:
        algo = digest.split(':', 1)[0].lower()
    else:
        algo = 'sha1'
    if algo not in hashlib.algorithms_available:
        raise ValueError('unsupported digest algorithm: ' + algo)
    return algo


def digest_value(digest):
    if ':' in digest:
        return digest.split(':', 1)[1]
    return digest


# =============================================================================
class VRReferenceCodec(object):
    """Mints and verifies verifiable replay reference tokens."""

    def __init__(self, secret=None):
        """
        :param str|bytes|None secret: shared secret used for the HMAC. When
            ``None`` a random per-process secret is used, which makes tokens
            issued by this process unverifiable after a restart.  Configure
            ``verifiable_replay_secret`` to get stable tokens.
        """
        if secret is None:
            secret = os.urandom(32)
        elif isinstance(secret, six.text_type):
            secret = secret.encode('utf-8')
        self.secret = secret

    # ----- minting ---------------------------------------------------------
    def mint(self, coll, url, timestamp, digest, rec_type,
             header_loc, payload_loc, payload_url, payload_ts,
             token_only=True):
        """Create a signed verifiable replay reference token.

        :param str coll: collection route name the token is bound to
        :param str url: captured target URI
        :param str timestamp: 14 digit capture timestamp
        :param str digest: payload fingerprint from the index
        :param str rec_type: ``response`` or ``revisit``
        :param tuple header_loc: ``(filename, offset, length)`` of the header
            record, exactly as stored in the index
        :param tuple payload_loc: ``(filename, offset, length)`` of the
            payload (donor) record
        :param str payload_url: WARC target URI of the payload record
        :param str payload_ts: 14 digit timestamp of the payload record
        """
        header_loc = self._loc_to_list(header_loc)
        payload_loc = self._loc_to_list(payload_loc)

        claims = {
            CLAIM_VERSION: 1,
            CLAIM_COLL: coll or '',
            CLAIM_TS: str(timestamp),
            CLAIM_URL: url,
            CLAIM_DIGEST: normalize_digest(digest),
            CLAIM_REC_TYPE: rec_type or 'response',
            CLAIM_HEADER: header_loc,
            # payload locator followed by its own target uri/timestamp so a
            # different-url donor can be pinned without another index lookup
            CLAIM_PAYLOAD: payload_loc + [payload_url or url,
                                          str(payload_ts or timestamp)],
        }
        self._validate_claims(claims)

        msg = _b64url_encode(json.dumps(claims,
                                        separators=(',', ':'),
                                        sort_keys=True).encode('utf-8'))

        sig = _b64url_encode(hmac.new(self.secret,
                                      VERSION.encode('ascii') + b'.' + msg.encode('ascii'),
                                      hashlib.sha256).digest())

        return VERSION + '.' + msg + '.' + sig

    @staticmethod
    def _loc_to_list(loc):
        filename, offset, length = loc
        return [str(filename), str(offset), str(length)]

    # ----- verification ----------------------------------------------------
    def decode(self, token):
        """Verify the signature and return the validated, native-form claims.

        :raises ValueError: if the token is malformed or the signature does
            not match (the token was tampered with or minted with another
            secret)
        """
        if not token or not isinstance(token, six.string_types):
            raise ValueError('empty reference')

        parts = token.split('.')
        if len(parts) != 3 or parts[0] != VERSION:
            raise ValueError('not a verifiable replay reference')

        version, msg, sig = parts

        try:
            expected_sig = _b64url_encode(hmac.new(
                self.secret,
                version.encode('ascii') + b'.' + msg.encode('ascii'),
                hashlib.sha256).digest())
        except Exception as e:
            raise ValueError('malformed verifiable replay reference: ' + str(e))

        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError('signature does not match verifiable replay '
                             'reference')

        # parse_claims() performs the structural validation of the signed
        # payload
        return parse_claims(version + '.' + msg + '.' + sig)

    # ----- validation ------------------------------------------------------
    @staticmethod
    def _validate_claims(claims):
        try:
            if claims[CLAIM_VERSION] != 1:
                raise ValueError('unsupported version')
            coll = claims[CLAIM_COLL]
            if not isinstance(coll, six.string_types):
                raise ValueError('collection must be a string')
            if not TS_RE.match(claims[CLAIM_TS]):
                raise ValueError('invalid timestamp')
            if not claims[CLAIM_URL]:
                raise ValueError('missing url')
            if not claims[CLAIM_DIGEST]:
                raise ValueError('missing digest')
            if claims[CLAIM_REC_TYPE] not in ('response', 'revisit'):
                raise ValueError('invalid record type')
            h = claims[CLAIM_HEADER]
            p = claims[CLAIM_PAYLOAD]
            if not isinstance(h, list) or len(h) != 3:
                raise ValueError('invalid header record locator')
            if not isinstance(p, list) or len(p) != 5:
                raise ValueError('invalid payload record locator')
            for index in (0, 1, 2):
                if not h[index] or not p[index]:
                    raise ValueError('invalid record locator')
            if not TS_RE.match(p[4]):
                raise ValueError('invalid payload timestamp')
        except (KeyError, TypeError) as e:
            raise ValueError('incomplete verifiable replay reference: ' + str(e))


# =============================================================================
def parse_claims(token):
    """Decode (without signature verification) and validate the claims.

    The front end needs the url/timestamp/collection for routing but must not
    depend on the server secret.  Signature verification happens when the
    warcserver replays the token, so decoding here is only used for routing
    information and never for trust decisions.
    """
    if not token or not isinstance(token, six.string_types):
        raise ValueError('empty reference')

    parts = token.split('.')
    if len(parts) != 3 or parts[0] != VERSION:
        raise ValueError('not a verifiable replay reference')

    try:
        claims = json.loads(_b64url_decode(parts[1]).decode('utf-8'))
    except Exception as e:
        raise ValueError('malformed reference payload: ' + str(e))

    VRReferenceCodec._validate_claims(claims)

    # return native python representations used throughout pywb
    return {
        'coll': claims[CLAIM_COLL],
        'ts': claims[CLAIM_TS],
        'url': claims[CLAIM_URL],
        'digest': claims[CLAIM_DIGEST],
        'rec_type': claims[CLAIM_REC_TYPE],
        'h': tuple(claims[CLAIM_HEADER]),
        'p': tuple(claims[CLAIM_PAYLOAD][:3]),
        'p_url': claims[CLAIM_PAYLOAD][3],
        'p_ts': claims[CLAIM_PAYLOAD][4],
    }


def strip_urn(replay_url_part):
    """Return the token from ``urn:vr:<token>`` or raise ValueError."""
    if not replay_url_part.startswith(VR_URN_PREFIX):
        raise ValueError('missing verifiable replay reference urn')
    token = replay_url_part[len(VR_URN_PREFIX):]
    if not token:
        raise ValueError('empty verifiable replay reference')
    return token
