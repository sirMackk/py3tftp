import hashlib
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


class TestRRQWindowsize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('README.md', 'rb') as f:
            cls.readme = f.read()
        cls.readme_md5 = hashlib.md5(cls.readme).hexdigest()
        cls.server_addr = ('127.0.0.1', 9069,)
        cls.rrq = h.RRQ + b'README.md\x00binary\x00'
        cls.window_rrq = (h.RRQ +
                       b'README.md\x00binary\x00windowsize\x00%d\x00')

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.counter = 0
        self.output = []
        self.data = None
        self.windowsize = 2
        window_rrq = self.window_rrq % self.windowsize
        self.s.sendto(window_rrq, self.server_addr)

    def tearDown(self):
        self.s.close()

    def ack_option(self):
        self.data, server = self.s.recvfrom(1024)
        msg = h.ACK + self.counter.to_bytes(2, byteorder='big')
        self.s.sendto(msg, server)
        self.counter += 1
        return

    def test_perfect_scenario(self):
        self.ack_option()
        while True:
            self.data, server = self.s.recvfrom(1024)
            if (self.counter % self.windowsize) == 0:  # end of window
                msg = h.ACK + self.counter.to_bytes(2, byteorder='big')
                self.s.sendto(msg, server)
            self.output += self.data[4:]
            self.counter += 1
            if len(self.data[4:]) < 512:
                break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.readme), len(received))
        self.assertTrue(self.readme_md5 == received_md5)

    def test_no_window_acks(self):
        self.ack_option()
        no_ack = True
        while True:
            self.data, server = self.s.recvfrom(1024)
            if self.counter % (2*self.windowsize) == 0 and no_ack:
                # dont ack, discard data
                no_ack = False
                self.data, server = self.s.recvfrom(1024)
            else:
                if (self.counter % self.windowsize) == 0:  # end of window
                    msg = h.ACK + self.counter.to_bytes(2, byteorder='big')
                    self.s.sendto(msg, server)
                no_ack = True
                self.output += self.data[4:]
                self.counter += 1

                if len(self.data[4:]) < 512:
                    self.counter -= 1
                    msg = h.ACK + self.counter.to_bytes(2, byteorder='big')
                    self.s.sendto(msg, server)
                    break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.readme), len(received))
        self.assertTrue(self.readme_md5 == received_md5)


if __name__ == '__main__':
    unittest.main()