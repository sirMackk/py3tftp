import unittest as t

from py3tftp.tftp_packet import (TFTPDatPacket, TFTPAckPacket, TFTPOckPacket,
    TFTPErrPacket, TFTPRequestPacket, BaseTFTPPacket)


class TestTFTPPacketService(t.TestCase):
    # test create_packet by mocking appropriate classes and checking for calls
    # test from_bytes by mocking create_packet and checking for calls
    pass


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
            BaseTFTPPacket.number_to_bytes(-10)

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

    def test_serialize_options_many_opt(self):
        opts = {'opt1': '123', 'opt2': 123}
        serialized_opts = BaseTFTPPacket.serialize_options(opts)
        self.assertEqual(b'opt1\x00123\x00opt2\x00123', serialized_opts)

    def test_serialize_options_zero(self):
        opts = {}
        serialized_opts = BaseTFTPPacket.serialize_options(opts)
        self.assertEqual(b'', serialized_opts)


class TestTFTPErrPacket(t.TestCase):
    def test_to_bytes(self):
        packet = TFTPErrPacket(code=1, msg='File not found')
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x05\x00\x01File not found')


class TestTFTPOckPacket(t.TestCase):
    def test_to_bytes_w_1_opt(self):
        packet = TFTPOckPacket(r_opts={'timeout', 25})
        serialized = packet.to_bytes()
        self.assertEqual(serialized, b'\x00\x06timeout\x0025\x00')

    def test_to_bytes_w_2_opts(self):
        packet = TFTPOckPacket(r_opts={'timeout': 25, 'blksize': 2048})
        serialized = packet.to_bytes()
        self.assertIn(b'timeout\x0025', serialized)
        self.assertIn(b'blksize\x002048', serialized)
        self.assertEqual(serialized[-1], b'\x00')
        self.assertEqual(serialized[:2], b'\x00\x06')


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
        packet = TFTPRequestPacket('rrq',
                                   fname='test',
                                   mode='test_mode',
                                   r_opts={'timeout': 25})
        serialized = packet.to_bytes()
        self.assertEqual(serialized,
                         b'\x00\x02test\x00test_mode\x00timeout\x0025\x00')
