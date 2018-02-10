import hashlib
import socket
import unittest
from io import BytesIO
from os import remove as rm
from os.path import exists
from time import sleep

import tests.test_helpers as h


class TestRRQ(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('LICENSE', 'rb') as f:
            cls.license = f.read()
        cls.license_md5 = hashlib.md5(cls.license).hexdigest()
        cls.server_addr = ('127.0.0.1', 9069,)
        cls.rrq = h.RRQ + b'LICENSE\x00binary\x00'

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.counter = 1
        self.output = []
        self.data = None
        self.s.sendto(self.rrq, self.server_addr)

    def tearDown(self):
        self.s.close()

    def test_perfect_scenario(self):
        while True:
            self.data, server = self.s.recvfrom(1024)
            self.output += self.data[4:]

            msg = h.ACK + self.counter.to_bytes(2, byteorder='big')
            self.s.sendto(msg, server)
            self.counter += 1

            if len(self.data[4:]) < 512:
                break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_no_acks(self):
        no_ack = True
        while True:
            self.data, server = self.s.recvfrom(1024)
            if self.counter % 5 == 0 and no_ack:
                # dont ack, discard data
                no_ack = False
            else:
                no_ack = True
                self.output += self.data[4:]

                msg = h.ACK + self.counter.to_bytes(2, byteorder='big')
                self.s.sendto(msg, server)
                self.counter += 1

                if len(self.data[4:]) < 512:
                    break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_total_timeout(self):
        max_msgs = 2
        while True:
            self.data, server = self.s.recvfrom(1024)
            if self.counter >= max_msgs:
                break

            self.output += self.data[4:]
            msg = h.ACK + self.counter.to_bytes(2, byteorder='big')

            self.s.sendto(msg, server)
            self.counter += 1

            if len(self.data[4:]) < 512:
                break
        received = bytes(self.output)
        self.assertEqual((max_msgs - 1) * 512, len(received))


class TestWRQ(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.license_buf = BytesIO()
        with open('LICENSE', 'rb') as f:
            license = f.read()
            cls.license_buf.write(license)
            cls.license_buf.seek(0)
            cls.license_md5 = hashlib.md5(license).hexdigest()
        cls.server_addr = ('127.0.0.1', 9069,)
        cls.wrq = h.WRQ + b'LICENSE_TEST\x00binary\x00'

    def setUp(self):
        if exists('LICENSE_TEST'):
            rm('LICENSE_TEST')
        self.license = iter(lambda: self.license_buf.read(512), b'')
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.sendto(self.wrq, self.server_addr)

    def tearDown(self):
        self.license_buf.seek(0)
        self.s.close()

    def test_perfect_transfer(self):
        for i, chunk in enumerate(self.license):
            ack, server = self.s.recvfrom(1024)
            self.assertEqual(ack, h.ACK + i.to_bytes(2, byteorder='big'))
            self.s.sendto(h.DAT + (i + 1).to_bytes(2, byteorder='big') + chunk,
                          server)

        sleep(1)
        with open('LICENSE_TEST', 'rb') as f:
            license_test = f.read()
            license_test_md5 = hashlib.md5(license_test).hexdigest()

        self.assertEqual(len(license_test), self.license_buf.tell())
        self.assertEqual(self.license_md5, license_test_md5)

    def test_lost_data_packet(self):
        last_pkt = None
        pkt = None
        counter = 0
        outbound_data = self.license
        while True:
            ack, server = self.s.recvfrom(1024)
            if counter > 0 and counter % 10 == 0 and pkt != last_pkt:
                pkt = last_pkt
            else:
                try:
                    pkt = next(outbound_data)
                except StopIteration:
                    break
                counter += 1

            self.s.sendto(h.DAT +
                          (counter).to_bytes(2,
                                             byteorder='big') + pkt,
                          server)
            last_pkt = pkt

        sleep(1)
        with open('LICENSE_TEST', 'rb') as f:
            license_test = f.read()
            license_test_md5 = hashlib.md5(license_test).hexdigest()

        self.assertEqual(len(license_test), self.license_buf.tell())
        self.assertEqual(self.license_md5, license_test_md5)

    def test_drop_client_connection(self):
        PKTS_BEFORE_DISCONNECT = 1
        for i, chunk in enumerate(self.license):
            ack, server = self.s.recvfrom(1024)
            if i >= PKTS_BEFORE_DISCONNECT:
                break
            self.s.sendto(h.DAT + (i + 1).to_bytes(2, byteorder='big') + chunk,
                          server)

        # wait for timeout to close file
        sleep(5.1)
        with open('LICENSE_TEST', 'rb') as f:
            license_test = f.read()

        self.assertEqual(len(license_test), self.license_buf.tell() - 512)


class TestTFTPErrors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 9069,)

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tearDown(self):
        self.s.close()

    def test_file_not_found(self):
        no_such_file = h.RRQ + b'NOSUCHFILE\x00binary\x00'
        self.s.sendto(no_such_file, self.server_addr)
        data, server = self.s.recvfrom(512)
        self.assertEqual(h.ERR + h.NOFOUND, data[:4])

    def test_file_already_exists(self):
        dup_file = h.WRQ + b'LICENSE\x00octet\x00'
        self.s.sendto(dup_file, self.server_addr)
        data, server = self.s.recvfrom(512)
        self.assertEqual(h.ERR + h.EEXISTS, data[:4])

    def test_unknown_transfer_id_rrq(self):
        legit_transfer = h.RRQ + b'LICENSE\x00octet\x00'
        self.s.sendto(legit_transfer, self.server_addr)
        data, server = self.s.recvfrom(1024)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(h.ACK + (1).to_bytes(2, byteorder='big'), server)
            err, server = s.recvfrom(32)
        finally:
            s.close()

        self.assertEqual(h.ERR + h.UNKNTID, err[:4])

    def test_unknown_transfer_id_wrq(self):
        if exists('LICENSE_TEST'):
            rm('LICENSE_TEST')
        legit_transfer = h.WRQ + b'LICENSE_TEST\x00octet\x00'
        self.s.sendto(legit_transfer, self.server_addr)
        ack, server = self.s.recvfrom(16)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(h.DAT +
                     (1).to_bytes(2, byteorder='big') + b'\x41\x41\x41',
                     server)
            err, server = s.recvfrom(32)
        finally:
            s.close()

        self.assertEqual(h.ERR + h.UNKNTID, err[:4])

    @unittest.skip('Gotta think of a way to test this')
    def test_access_violation(self):
        no_perms = h.RRQ + b'NOPERMS\x00binary\x00'
        self.s.sendto(no_perms, self.server_addr)
        data, server = self.s.recvfrom(512)
        self.assertEqual(h.ERR + h.ACCVIOL, data[:4])

    @unittest.skip('')
    def test_illegal_tftp_operation(self):
        pass

    @unittest.skip('')
    def test_undefined_error(self):
        pass

    @unittest.skip('')
    def test_disk_full(self):
        pass


if __name__ == '__main__':
    unittest.main()
