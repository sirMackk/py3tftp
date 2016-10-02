import unittest as t
from unittest.mock import MagicMock

from py3tftp.protocols import (
    TFTPServerProtocol, RRQProtocol, WRQProtocol)
from py3tftp.tftp_packet import TFTPPacketFactory

from tests.test_helpers import (RRQ, WRQ, DAT, ACK)


class TestTFTPServerProtocol(t.TestCase):
    def setUp(self):
        self.protocol = TFTPServerProtocol('host', None, {})

    def test_select_protocol_wrq(self):
        request_packet_mock = MagicMock()
        request_packet_mock.is_rrq = lambda: True
        request_packet_mock.is_wrq = lambda: False
        klass = self.protocol.select_protocol(request_packet_mock)
        self.assertTrue(klass == RRQProtocol)

    def test_select_protocol_rrq(self):
        request_packet_mock = MagicMock()
        request_packet_mock.is_wrq = lambda: True
        request_packet_mock.is_rrq = lambda: False
        klass = self.protocol.select_protocol(request_packet_mock)
        self.assertTrue(klass == WRQProtocol)

    def test_datagram_received(self):
        data = b'\x00\x01TEST\x00binary\x00'
        mock_loop = MagicMock()
        mock_loop.create_datagram_endpoint.return_value = ('endpoint',)
        mock_loop.create_task.return_value = True

        proto = TFTPServerProtocol('127.0.0.1', mock_loop, {})

        proto.datagram_received(data, ('127.0.0.1', 0,))
        self.assertTrue(mock_loop.create_datagram_endpoint.called)
        mock_loop.create_task.assert_called_with(('endpoint',))


class TestWRQProtocol(t.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet_factory = TFTPPacketFactory()

    def setUp(self):
        self.addr = ('127.0.0.1', 9999,)
        self.wrq = self.packet_factory.from_bytes(
            WRQ + b'\x00filename1\x00octet\x00')
        self.proto = WRQProtocol(self.wrq, self.addr, {})
        self.proto.set_proto_attributes()
        self.proto.h_timeout = MagicMock()
        self.proto.counter = 10
        self.proto.transport = MagicMock()
        self.proto.file_iterator = MagicMock()

    def test_reply_after_write(self):
        data = DAT + b'\x00\x0BAAAA'
        self.proto.datagram_received(data, self.addr)

        self.assertEqual(self.proto.counter, 11)
        self.proto.transport.sendto.assert_called_with(ACK + b'\x00\x0b',
                                                       self.addr)

    def test_close_transport_after_file_finished(self):
        self.proto.file_iterator.send.side_effect = StopIteration()
        data = DAT + b'\x00\x0BAAAA'
        self.proto.datagram_received(data, self.addr)

        self.assertTrue(self.proto.transport.close.called)

    def test_correct_packet_received_and_saved(self):
        data = DAT + b'\x00\x0BAAAA'
        self.proto.datagram_received(data, self.addr)

        self.proto.file_iterator.send.assert_called_with(b'AAAA')

    def test_bad_tid(self):
        data = DAT + b'\x00\x0BAAAA'
        addr = ('127.0.0.1', 8888,)
        self.proto.datagram_received(data, addr)

        err_tid = self.packet_factory.err_unknown_tid()

        self.proto.transport.sendto.assert_called_with(err_tid.to_bytes(),
                                                       addr)

    def test_bad_packet(self):
        data = ACK + b'\x00\x0C'
        self.proto.datagram_received(data, self.addr)

        self.assertFalse(self.proto.transport.sendto.called)
        self.assertFalse(self.proto.file_iterator.send.called)

    def test_bad_packet_sequence_is_ignored(self):
        data = DAT + b'\x00\x0CAAAA'
        self.proto.datagram_received(data, self.addr)

        self.assertFalse(self.proto.transport.sendto.called)
        self.assertFalse(self.proto.file_iterator.send.called)
