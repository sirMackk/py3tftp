import socket
import unittest

import tests.test_helpers as h


class TestWindowsize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('LICENSE', 'rb') as f:
            cls.license = f.read()
        cls.server_addr = ('127.0.0.1', 9069,)
        cls.window_rrq = (h.RRQ +
                       b'LICENSE\x00octet\x00windowsize\x00%d\x00')

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tearDown(self):
        self.s.close()

    def test_negative_windowsize(self):
        windowsize = -1
        window_rrq = self.window_rrq % windowsize
        self.s.sendto(window_rrq, self.server_addr)
        data, addr = self.s.recvfrom(16)
        self.assertEqual(h.DAT + b'\x00\x01', data[:4])

    def test_zero_windowsize(self):
        windowsize = 0
        window_rrq = self.window_rrq % windowsize
        self.s.sendto(window_rrq, self.server_addr)
        data, addr = self.s.recvfrom(1024)
        self.assertEqual(h.DAT + b'\x00\x01', data[:4])

    def test_smaller_windowsize_suggested(self):
        # max is 65535 as spec'd by RFC7440
        windowsize = 65536
        window_rrq = self.window_rrq % windowsize
        self.s.sendto(window_rrq, self.server_addr)
        ock, addr = self.s.recvfrom(32)
        self.assertEqual(h.OCK, ock[:2])
        self.assertIn(b'65535', ock)

    def test_oack_windowsize(self):
        windowsize = 1234
        window_rrq = self.window_rrq % windowsize
        self.s.sendto(window_rrq, self.server_addr)
        ock, addr = self.s.recvfrom(32)
        ack = h.ACK + b'\x00\x00'
        self.assertEqual(h.OCK, ock[:2]) 
        self.assertIn(b'1234', ock)


if __name__ == '__main__':
    unittest.main()