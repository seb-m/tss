"""
Threshold Secret Sharing (Shamir's secret sharing scheme)
http://tools.ietf.org/html/draft-mcgrew-tss-03

Example:
    import tss
    # Create 8 shares of the secret recoverable from at least 5
    # differents shares. Use secretid42 as identifier and hash the
    # secret with sha256.
    shares = tss.share_secret(5, 8, 'my shared secret', 'secretid42',
                              tss.Hash.SHA256)
    try:
        # Recover the secret value
        secret = tss.reconstruct_secret(shares)
    except tss.TSSError:
        pass  # Handling error

Notes:
 - Operations are _not_ constant-time, and are quite verbose too
 - This implementation doesn't provide ECC encoding/decoding
"""
import hashlib
import itertools
import os
import struct
import sys

__author__ = 'Sebastien Martini (seb@dbzteam.org)'
__version__ = '0.1'
__license__ = 'MIT'
__all__ = ['share_secret', 'reconstruct_secret', 'Hash', 'TSSError']


# Compatibility

if sys.version_info < (3, 0):
    b = lambda x: x
    byte_to_chr = lambda x: x
    byte_to_ord = lambda x: ord(x)
    basestring = basestring
    unicode = unicode
    bytes = str
    digest_size = lambda d: d.digestsize
else:
    b = lambda x: x.encode('iso8859-1')
    byte_to_chr = lambda x: chr(x)
    byte_to_ord = lambda x: x
    basestring = str
    unicode = str
    bytes = bytes
    digest_size = lambda d: d.digest_size

def encode(value, encoding='utf-8', encoding_errors='strict'):
    """
    Return a bytestring representation of the value.
    """
    if isinstance(value, bytes):
        return value
    if not isinstance(value, basestring):
        value = str(value)
    if isinstance(value, unicode):
        value = value.encode(encoding, encoding_errors)
    return value


# GF(256) arithmetic

EXP = [0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
       0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
       0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
       0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
       0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
       0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
       0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
       0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
       0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
       0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
       0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
       0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
       0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
       0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
       0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
       0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
       0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
       0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
       0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
       0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
       0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
       0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
       0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
       0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
       0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
       0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
       0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
       0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
       0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
       0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
       0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
       0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x00]

LOG = [  0,    0,   25,    1,   50,    2,   26,  198,
        75,  199,   27,  104,   51,  238,  223,    3,
       100,    4,  224,   14,   52,  141,  129,  239,
        76,  113,    8,  200,  248,  105,   28,  193,
       125,  194,   29,  181,  249,  185,   39,  106,
        77,  228,  166,  114,  154,  201,    9,  120,
       101,   47,  138,    5,   33,   15,  225,   36,
        18,  240,  130,   69,   53,  147,  218,  142,
       150,  143,  219,  189,   54,  208,  206,  148,
        19,   92,  210,  241,   64,   70,  131,   56,
       102,  221,  253,   48,  191,    6,  139,   98,
       179,   37,  226,  152,   34,  136,  145,   16,
       126,  110,   72,  195,  163,  182,   30,   66,
        58,  107,   40,   84,  250,  133,   61,  186,
        43,  121,   10,   21,  155,  159,   94,  202,
        78,  212,  172,  229,  243,  115,  167,   87,
       175,   88,  168,   80,  244,  234,  214,  116,
        79,  174,  233,  213,  231,  230,  173,  232,
        44,  215,  117,  122,  235,   22,   11,  245,
        89,  203,   95,  176,  156,  169,   81,  160,
       127,   12,  246,  111,   23,  196,   73,  236,
       216,   67,   31,   45,  164,  118,  123,  183,
       204,  187,   62,   90,  251,   96,  177,  134,
        59,   82,  161,  108,  170,   85,   41,  157,
       151,  178,  135,  144,   97,  190,  220,  252,
       188,  149,  207,  205,   55,   63,   91,  209,
        83,   57,  132,   60,   65,  162,  109,   71,
        20,   42,  158,   93,   86,  242,  211,  171,
        68,   17,  146,  217,   35,   32,   46,  137,
       180,  124,  184,   38,  119,  153,  227,  165,
       103,   74,  237,  222,  197,   49,  254,   24,
        13,   99,  140,  128,  192,  247,  112,    7]

def gf256_add(a, b):
    return a ^ b

def gf256_sub(a, b):
    return gf256_add(a, b)

def gf256_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[(LOG[a] + LOG[b]) % 255]

def gf256_div(a, b):
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError
    return EXP[(LOG[a] - LOG[b]) % 255]


# TSS error

class TSSError(Exception):
    pass


# Hash

class Hash(object):
    NONE = 0
    SHA1 = 1
    SHA256 = 2

    @staticmethod
    def to_func(hash_id):
        if hash_id == 1:
            return hashlib.sha1
        if hash_id == 2:
            return hashlib.sha256
        raise TSSError('invalid hash algorithm %d' % hash_id)

    @staticmethod
    def is_valid(hash_id):
        return 0 <= hash_id <= 2


# Share generation

def f(x, coefs_bytes):
    if x == 0:
        raise TSSError('invalid share index value, cannot be 0')
    y = 0
    x_i = 1
    for c in coefs_bytes:
        y = gf256_add(y, gf256_mul(byte_to_ord(c), x_i))
        x_i = gf256_mul(x_i, x)
    return y

def generate_shares(m, n, secret):
    if len(secret) > (2**16 - 2) or m < 1 or m > 254 or n < m or n > 254:
        raise TSSError('invalid share parameter')
    shares = []
    for i in range(1, n + 1):
        share = bytearray()
        share.append(i)
        shares.append(share)
    for secret_byte in secret:
        r = os.urandom(m - 1)
        for i in range(n):
            shares[i].append(f(shares[i][0],
                               b(byte_to_chr(secret_byte)) + r))
    return [bytes(share) for share in shares]

def format_header(identifier, hash_id, threshold, share_len):
    return struct.pack('>16sBBH', identifier, hash_id, threshold, share_len)

def format_share(header, share):
    return header[:] + share

def share_secret(threshold, nshares, secret, identifier, hash_id=Hash.SHA256):
    """
    Create nshares of the secret. threshold specifies the number of shares
    needed for reconstructing the secret value. A 0-16 bytes identifier must
    be provided. Optionally the secret is hashed with the algorithm specified
    by hash_id, a class attribute of Hash.
    This function must return a list of formatted shares or raises a TSSError
    exception if anything went wrong.
    """
    if identifier is None:
        raise TSSError('an identifier must be provided')
    if not Hash.is_valid(hash_id):
        raise TSSError('invalid hash algorithm %s' % hash_id)
    secret = encode(secret)
    identifier = encode(identifier)
    if hash_id != Hash.NONE:
        secret += Hash.to_func(hash_id)(secret).digest()
    shares = generate_shares(threshold, nshares, secret)
    header = format_header(identifier, hash_id, threshold, len(secret) + 1)
    return [format_share(header, share) for share in shares]


# Secret reconstruction

def basis_poly(i, u):
    prod = 1
    for j in range(len(u)):
        if i == j:
            continue
        prod = gf256_mul(prod, gf256_div(u[j], gf256_add(u[j], u[i])))
    return prod

def lagrange_interpolation(u, v):
    sum = 0
    for i in range(len(v)):
        sum = gf256_add(sum, gf256_mul(basis_poly(i, u), v[i]))
    return sum

def parse_header(share):
    return struct.unpack('>16sBBH', share)

def reconstruct_secret(shares, strict_mode=True):
    """
    shares must be a container with a sufficient number of well-formatted
    shares used to reconstruct the secret value. If any share format is
    invalid a TSSError exception is raised.
    If strict_mode is False all combinations of shares are tried in order
    to reconstruct the secret. Otherwise this function raises an exception
    TSSError on the first error encountered (either a duplicate share was
    detected or the provided hash value didn't match the one computed from
    the recovered secret).
    This function must return the secret value or raise TSSError.
    """
    ref_header = None
    data_shares = []
    for share in shares:
        share = encode(share)
        if len(share) < 20:
            raise TSSError('share format invalid')
        header = parse_header(share[:20])
        if ref_header is None:
            ref_header = header
            if header[2] > len(shares):
                raise TSSError('not enough shares for reconstructing secret')
        if ref_header != header:
            raise TSSError('invalid share headers %s' % header)
        data_share = share[20:]
        if len(data_share) != header[3]:
            raise TSSError('invalid share data size %d (expected %d)' % \
                               (len(data_share), header[3]))
        data_shares.append(data_share)

    for combination in itertools.combinations(data_shares, ref_header[2]):
        secret = bytearray()
        u = [byte_to_ord(share[0]) for share in combination]
        if len(dict().fromkeys(u)) != len(u):
            if strict_mode:
                raise TSSError('invalid share with duplicate index')
            else:
                continue
        for i in range(1, ref_header[3]):
            v = [byte_to_ord(share[i]) for share in combination]
            secret.append(lagrange_interpolation(u, v))
        secret = bytes(secret)
        if ref_header[1] != Hash.NONE:
            d = Hash.to_func(ref_header[1])()
            digestsize = digest_size(d)
            d.update(secret[:-digestsize])
            if len(secret) < digestsize or d.digest() != secret[-digestsize:]:
                if strict_mode:
                    raise TSSError('hash values mismatch')
                else:
                    continue
            return secret[:-digestsize]
        return secret
    raise TSSError('not enough valid shares for reconstructing the secret')
