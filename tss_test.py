import unittest
import tss
from tss import share_secret, reconstruct_secret, Hash, TSSError


class TSSTestCase(unittest.TestCase):
    def test_tss1(self):
        # test\0
        secret = b'\x74\x65\x73\x74\x00'
        shares = share_secret(2, 2, secret, 'my-id', Hash.NONE)
        reconstructed_secret = reconstruct_secret(shares)
        self.assertEqual(secret, reconstructed_secret)

    def test_tss2(self):
        secret = b'my big fat secret'
        h = (b'\x6c\x53\x71\x42\x9e\xff\xfb\xb2\x5b\x7d\xea\x79\xc0\x50\xee'
             b'\xd3\xed\x83\x30\xfe\x7b\xdf\x4d\x02\x32\x30\x89\x36\x9e\x5c'
             b'\x73\x48')
        shares1 = share_secret(5, 10, secret, 'my-id', Hash.SHA256)
        shares2 = share_secret(5, 10, secret + h, 'my-id', Hash.NONE)
        reconstructed_secret1 = reconstruct_secret(shares1)
        reconstructed_secret2 = reconstruct_secret(shares2)
        self.assertEqual(secret, reconstructed_secret1)
        self.assertEqual(secret + h, reconstructed_secret2)

    def test_tss3(self):
        secret = b'\x74\x65\x73\x74\x00'
        shares = [b'my-id\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                  b'\x02\x00\x06\x01\xb9\xfa\x07\xe1\x85',
                  b'my-id\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                  b'\x00\x02\x00\x06\x02\xf5\x40\x9b\x45\x11']
        reconstructed_secret = reconstruct_secret(shares)
        self.assertEqual(secret, reconstructed_secret)

    def test_tss4(self):
        secret = b'my big fat secret'
        shares = share_secret(5, 10, secret, 'my-id')
        share_mod = shares[0]
        share_mod = (share_mod[:-4] +
                     tss.b(chr(~tss.byte_to_ord(share_mod[-4]) % 256)) +
                     share_mod[-3:])
        shares[0] = share_mod
        self.assertRaises(TSSError, lambda: reconstruct_secret(shares, True))
        reconstructed_secret = reconstruct_secret(shares, False)
        self.assertEqual(secret, reconstructed_secret)
        self.assertRaises(TSSError,
                          lambda: reconstruct_secret(shares[:5], False))


if __name__ == '__main__':
    unittest.main()
