import unittest
import socket
import struct
import hashlib
from io import BytesIO
from os import remove as rm


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
        self.output = []
        self.data = None
        self.s.sendto(self.rrq, self.serverAddr)

    def tearDown(self):
        self.s.close()

    def test_perfect_scenario(self):
        while True:
            self.data, server = self.s.recvfrom(512)
            self.output += self.data

            msg = ACK + struct.pack('=H', self.counter)
            self.s.sendto(msg, server)
            self.counter += 1

            if len(self.data) < 512:
                break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_no_acks(self):
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

                if len(self.data) < 512:
                    break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_total_timeout(self):
        max_msgs = 15
        while True:
            self.data, server = self.s.recvfrom(512)
            if self.counter >= max_msgs:
                break

            self.output += self.data
            msg = ACK + struct.pack('=H', self.counter)
            self.s.sendto(msg, server)
            self.counter += 1

            if len(self.data) < 512:
                break

        received = bytes(self.output)
        self.assertEqual((max_msgs - 1) * 512, len(received))


# class TestWRQ(unittest.TestCase):
    # @classmethod
    # def setUpClass(cls):
        # cls.license = BytesIO()
        # with open('LICENSE', 'rb') as f:
            # license = f.read()
            # cls.license.write(license)
            # cls.license.seek(0)
            # cls.license_md5 = hashlib.md5(license).hexdigest()
        # cls.serverAddr = ('127.0.0.1', 8069,)
        # cls.wrq = b'\x02\x00LICENSE_TEST\x00binary\x00'

    # def setUp(self):
        # self.license = iter(lambda: self.license.read(512), '')
        # self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.counter = 0
        # self.s.sendto(self.wrq, self.serverAddr)

    # def tearDown(self):
        # self.license.seek(0)
        # self.s.close()
        # rm('LICENSE_TEST')

    # def test_perfect_transfer(self):
        # ack, server = self.s.recvfrom(512)
        # for chunk in self.license:
            # self.assertEqual(ack, ACK + struct.pack('=H', self.counter))
            # self.s.sendto(chunk, server)

        # with open('LICENSE_TEST', 'rb') as f:
            # license_test = f.read()
            # license_test_md5 = hashlib.md5(license_test).hexdigest()

        # self.assertEqual(len(license_test), self.license.len)
        # self.assertEqual(self.license_md5, license_test_md5)

if __name__ == '__main__':
    unittest.main()
