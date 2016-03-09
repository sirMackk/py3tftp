import unittest
import socket

import test_helpers as h


class TestBlksize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('LICENSE', 'rb') as f:
            cls.license = f.read()
        cls.server_addr = ('127.0.0.1', 9069,)
        cls.blk_rrq = (h.RRQ +
                       b'LICENSE\x00octet\x00blksize\x00%d\x00')

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tearDown(self):
        self.s.close()

    def test_negative_blksize(self):
        blksize = -1
        blk_rrq = self.blk_rrq % blksize
        self.s.sendto(blk_rrq, self.server_addr)
        data, addr = self.s.recvfrom(16)
        self.assertEqual(h.DAT + b'\x00\x01', data[:4])

    def test_zero_blksize(self):
        blksize = 0
        blk_rrq = self.blk_rrq % blksize
        self.s.sendto(blk_rrq, self.server_addr)
        data, addr = self.s.recvfrom(1024)
        self.assertEqual(h.DAT + b'\x00\x01', data[:4])

    def test_smaller_blksize_suggested(self):
        # max is 65464 as spec'd by RFC2348
        blksize = 65465
        blk_rrq = self.blk_rrq % blksize
        self.s.sendto(blk_rrq, self.server_addr)
        ock, addr = self.s.recvfrom(16)
        self.assertEqual(h.OCK, ock[:2])
        self.assertIn(b'65464', ock)

    def test_blksize_same_as_filesize(self):
        blksize = 1075
        blk_rrq = self.blk_rrq % blksize
        self.s.sendto(blk_rrq, self.server_addr)
        ock, addr = self.s.recvfrom(1024)

    def test_effective_blksize(self):
        blksize = 675
        blk_rrq = self.blk_rrq % blksize
        self.s.sendto(blk_rrq, self.server_addr)
        ock, addr = self.s.recvfrom(16)
        ack = h.ACK + b'\x00\x00'
        self.s.sendto(ack, addr)
        data, _ = self.s.recvfrom(blksize + 4)
        self.assertEqual(h.DAT, data[:2])
        self.assertEqual(self.license[:blksize], data[4:])

    @unittest.skip('Figure out cancelling connections serverside')
    def test_client_refuse_blksize(self):
        blksize = 675
        blk_rrq = self.blk_rrq % blksize
        self.s.sendto(blk_rrq, self.server_addr)
        ock, addr = self.s.recvfrom(16)
        err = h.ERR + h.OPTNERR
        self.s.sendto(err, addr)


if __name__ == '__main__':
    unittest.main()
