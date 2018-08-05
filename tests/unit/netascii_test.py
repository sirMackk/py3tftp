# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import io
import unittest as t

from py3tftp.netascii import Netascii

class NetasciiTest(t.TestCase):
    octet_to_netascii = {
        b"\r":     b"\r\x00",
        b"\n":     b"\r\n",
        b"te\nst": b"te\r\nst",
        b"te\rst": b"te\r\x00st",
        b"\r\r\r": b"\r\x00\r\x00\r\x00",
        b"\n\n\n": b"\r\n\r\n\r\n",
    }

    def test_netascii_reader(self):
        for octet, netascii in self.octet_to_netascii.items():
            for blksize in [1,2,3,4]:
                octet_buffer = io.BytesIO(octet)
                netascii_buffer = b''
                reader = Netascii(octet_buffer)
                while True:
                    data = reader.read(blksize)
                    if len(data):
                        netascii_buffer += data
                    else:
                        break
                self.assertEqual(netascii, netascii_buffer)

    def test_netascii_writer(self):
        for octet, netascii in self.octet_to_netascii.items():
            for blksize in [1,2,3,4]:
                octet_buffer = io.BytesIO()
                writer = Netascii(octet_buffer)
                for i in range(0, len(netascii), blksize):
                    chunk = netascii[i:i+blksize]
                    writer.write(chunk)
                self.assertEqual(octet, octet_buffer.getvalue())
