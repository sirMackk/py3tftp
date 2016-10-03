from collections import OrderedDict
import unittest as t
from unittest.mock import patch, MagicMock

from py3tftp.exceptions import BadRequest
from py3tftp.tftp_packet import (TFTPDatPacket, TFTPAckPacket, TFTPOckPacket,
    TFTPErrPacket, TFTPRequestPacket, BaseTFTPPacket, TFTPPacketFactory)


class TestTFTPPacketService(t.TestCase):
    def setUp(self):
        self.packet_factory = TFTPPacketFactory()

    @patch('py3tftp.tftp_packet.TFTPRequestPacket')
    def test_create_request_packet(self, req_packet):
        self.packet_factory.create_packet('RRQ', fname='test', mode='test')
        req_packet.assert_called_once_with('RRQ', fname='test', mode='test')

    @patch('py3tftp.tftp_packet.TFTPDatPacket')
    def test_create_dat_packet(self, dat_packet):
        self.packet_factory.create_packet('DAT', block_no=1, data=b'test')
        dat_packet.assert_called_once_with(block_no=1, data=b'test')

    @patch('py3tftp.tftp_packet.TFTPAckPacket')
    def test_create_ack_packet(self, ack_packet):
        self.packet_factory.create_packet('ACK', block_no=1)
        ack_packet.assert_called_once_with(block_no=1)

    @patch('py3tftp.tftp_packet.TFTPOckPacket')
    def test_create_ock_packet(self, ock_packet):
        self.packet_factory.create_packet('OCK', r_opts ={'tsize': 512})
        ock_packet.assert_called_once_with(r_opts={'tsize': 512})

    @patch('py3tftp.tftp_packet.TFTPErrPacket')
    def test_create_err_packet(self, err_packet):
        self.packet_factory.create_packet('ERR', code=1, msg='Error')
        err_packet.assert_called_once_with(code=1, msg='Error')

    def test_from_bytes_rrq(self):
        pkt = self.packet_factory.from_bytes(
            b'\x00\x01TEST\x00binary\x00')
        self.assertTrue(pkt.is_rrq())

    def test_from_bytes_wrq(self):
        pkt = self.packet_factory.from_bytes(
            b'\x00\x02TEST\x00binary\x00')
        self.assertTrue(pkt.is_wrq())

    def test_from_bytes_dat(self):
        pkt = self.packet_factory.from_bytes(
            b'\x00\x03\x00\x01chunk')
        self.assertTrue(pkt.is_data())

    def test_from_bytes_ack(self):
        pkt = self.packet_factory.from_bytes(
            b'\x00\x04\x00\x01')
        self.assertTrue(pkt.is_ack())

    def test_from_bytes_err(self):
        pkt = self.packet_factory.from_bytes(
            b'\x00\x05\x00\x01error_msg\x00')
        self.assertTrue(pkt.is_err())

    def test_from_bytes_ock(self):
        pkt = self.packet_factory.from_bytes(
            b'\x00\x06blksize\x00512\x00')
        self.assertTrue(pkt.is_ock())

    def test_from_bytes_bad_packet(self):
        with self.assertRaises(BadRequest):
            pkt = self.packet_factory.from_bytes(
                b'\x00\x00\x00blksize\x00512\x00')


class TestBaseTFTPPacket(t.TestCase):
    def test_number_to_bytes(self):
        byte_no = BaseTFTPPacket.number_to_bytes(50)
        self.assertEqual(b'50', byte_no)

    def test_pack_short(self):
        packed_short = BaseTFTPPacket.pack_short(10)
        self.assertEqual(b'\x00\x0A', packed_short)

    def test_pack_short_large_no(self):
        packed_short = BaseTFTPPacket.pack_short(15421)
        self.assertEqual(b'\x3c\x3d', packed_short)

    def test_pack_neg_short_error(self):
        with self.assertRaises(OverflowError):
            BaseTFTPPacket.pack_short(-10)

    def test_unpack_short(self):
        unpacked_short = BaseTFTPPacket.unpack_short(b'\x00\x0A')
        self.assertEqual(10, unpacked_short)

    def test_unpack_short_large_no(self):
        unpacked_short = BaseTFTPPacket.unpack_short(b'\x3c\x3d')
        self.assertEqual(15421, unpacked_short)

    def test_serialize_options_one_opt(self):
        opts = {'opt1': 123}
        serialized_opts = BaseTFTPPacket.serialize_options(opts)
        self.assertEqual(b'opt1\x00123', serialized_opts)

    def test_serialize_options_bytes(self):
        opts = {b'opt1': 123}
        serialized_opts = BaseTFTPPacket.serialize_options(opts)
        self.assertEqual(b'opt1\x00123', serialized_opts)

    def test_serialize_options_many_opt(self):
        opts = OrderedDict()
        opts['opt1'] = '321'
        opts['opt2'] = 123
        serialized_opts = BaseTFTPPacket.serialize_options(opts)
        self.assertEqual(b'opt1\x00321\x00opt2\x00123', serialized_opts)

    def test_serialize_options_zero(self):
        opts = {}
        serialized_opts = BaseTFTPPacket.serialize_options(opts)
        self.assertEqual(b'', serialized_opts)


class TestTFTPErrPacket(t.TestCase):
    def test_to_bytes(self):
        packet = TFTPErrPacket(code=1, msg='File not found')
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x05\x00\x01File not found\x00')


class TestTFTPOckPacket(t.TestCase):
    def test_to_bytes_w_1_opt(self):
        packet = TFTPOckPacket(r_opts={'timeout': 25})
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x06timeout\x0025\x00')

    def test_to_bytes_w_2_opts(self):
        packet = TFTPOckPacket(r_opts={'timeout': 25, 'blksize': 2048})
        serialized = packet.to_bytes()
        self.assertIn(b'timeout\x0025', serialized)
        self.assertIn(b'blksize\x002048', serialized)
        self.assertEqual(serialized[-1], 0)
        self.assertIn(b'\x00\x06', serialized[:2])


class TestTFTPDatPacket(t.TestCase):
    def test_no_data(self):
        packet = TFTPDatPacket(block_no=25, data=b'')
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x03\x00\x19')

    def test_w_data(self):
        packet = TFTPDatPacket(block_no=25, data=b'a lot of data')
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x03\x00\x19a lot of data')


class TestTFTPAckPacket(t.TestCase):
    def test_ack(self):
        packet = TFTPAckPacket(block_no=555)
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x04\x02\x2b')


class TestTFTPRequestPacket(t.TestCase):
    def test_rrq_without_opts(self):
        packet = TFTPRequestPacket('rrq', fname='test', mode='test_mode')
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x01test\x00test_mode\x00')

    def test_rrq_with_opts(self):
        packet = TFTPRequestPacket('rrq',
                                   fname='test',
                                   mode='test_mode',
                                   r_opts={'timeout': 25})
        serialized = packet.to_bytes()
        self.assertEqual(serialized,
                         b'\x00\x01test\x00test_mode\x00timeout\x0025\x00')

    def test_wrq_without_opts(self):
        packet = TFTPRequestPacket('wrq', fname='test', mode='test_mode')
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x02test\x00test_mode\x00')

    def test_wrq_with_opts(self):
        packet = TFTPRequestPacket('wrq',
                                   fname='test',
                                   mode='test_mode',
                                   r_opts={'timeout': 25})
        serialized = packet.to_bytes()
        self.assertEqual(serialized,
                         b'\x00\x02test\x00test_mode\x00timeout\x0025\x00')


if __name__ == '__main__':
    t.main()
