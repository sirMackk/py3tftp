import unittest
import socket

import tests.test_helpers as h


class TestOptions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 9069,)

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tearDown(self):
        self.s.close()

    def test_oack_echos_supported_opts(self):
        opts_rrq = (h.RRQ +
                    b'LICENSE\x00ocetet\x00timeout\x0012\x00unsprt\x0099\x00')
        self.s.sendto(opts_rrq, self.server_addr)
        data, _ = self.s.recvfrom(512)
        self.assertEqual(h.OCK, data[:2])
        self.assertIn(b'timeout', data)
        self.assertIn(b'12', data)
        self.assertNotIn(b'unsprt', data)
        self.assertNotIn(b'99', data)

    def test_missing_pair(self):
        opts_rrq = (h.RRQ +
                    b'LICENSE\x00octet\x00timeout\x00')
        self.s.sendto(opts_rrq, self.server_addr)
        data, _ = self.s.recvfrom(512)
        self.assertEqual(h.DAT, data[:2])

    def test_missing_opt_pair(self):
        opts_rrq = (h.RRQ +
                    b'LICENSE\x00octet\x00timeout\x0012\00blksize\x00')
        self.s.sendto(opts_rrq, self.server_addr)
        data, _ = self.s.recvfrom(512)
        self.assertEqual(h.OCK, data[:2])
        self.assertIn(b'timeout', data)
        self.assertIn(b'12', data)
        self.assertNotIn(b'blksize', data)


if __name__ == '__main__':
    unittest.main()
