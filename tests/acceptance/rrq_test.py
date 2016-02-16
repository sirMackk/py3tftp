import unittest
import socket
import struct
import hashlib


ACK = b'\x04\x00'


class TestRRQ(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('LICENSE', 'rb') as f:
            cls.license = f.read()
        cls.license_md5 = hashlib.md5(cls.license).hexdigest()
        cls.serverAddr = ('127.0.0.1', 8069,)
        cls.rrq = b'\x01\x00LICENSE\x00binary\x00'

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.counter = 1
        self.data_counter = 0
        self.output = []
        self.data = None

    def tearDown(self):
        self.s.close()

    def test_perfect_scenario(self):
        self.s.sendto(self.rrq, self.serverAddr)

        while True:
            self.data, server = self.s.recvfrom(512)
            self.output += self.data

            msg = ACK + struct.pack('=H', self.counter)
            self.s.sendto(msg, server)
            self.counter += 1

            self.data_counter += len(self.data)
            if len(self.data) < 512:
                break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_no_acks(self):
        self.s.sendto(self.rrq, self.serverAddr)
        no_ack = True

        while True:
            self.data, server = self.s.recvfrom(512)
            if self.counter % 5 == 0 and no_ack:
                # dont ack, discard data
                no_ack = False
            else:
                no_ack = True
                self.output += self.data

                msg = ACK + struct.pack('=H', self.counter)
                self.s.sendto(msg, server)
                self.counter += 1

                self.data_counter += len(self.data)
                if len(self.data) < 512:
                    break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_total_timeout(self):
        max_msgs = 15
        self.s.sendto(self.rrq, self.serverAddr)
        while True:
            self.data, server = self.s.recvfrom(512)
            if self.counter >= max_msgs:
                break

            self.output += self.data
            msg = ACK + struct.pack('=H', self.counter)
            self.s.sendto(msg, server)
            self.counter += 1

            self.data_counter += len(self.data)
            if len(self.data) < 512:
                break

        received = bytes(self.output)
        self.assertEqual((max_msgs - 1) * 512, len(received))

if __name__ == '__main__':
    unittest.main()
