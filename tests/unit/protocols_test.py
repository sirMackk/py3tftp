import unittest as t
from unittest.mock import MagicMock, call

from py3tftp.protocols import (
    TFTPServerProtocol, RRQProtocol, WRQProtocol)
from py3tftp.tftp_packet import TFTPPacketFactory
from py3tftp.file_io import FileReader, FileWriter

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
        self.wrq = WRQ + b'\x00filename1\x00octet\x00'
        self.proto = WRQProtocol(self.wrq, MagicMock, self.addr, {})
        self.proto.set_proto_attributes()
        self.proto.h_timeout = MagicMock()
        self.proto.file_handler = MagicMock()
        self.proto.counter = 10
        self.proto.transport = MagicMock()

    def test_reply_after_write(self):
        data = DAT + b'\x00\x0BAAAA'
        self.proto.datagram_received(data, self.addr)

        self.assertEqual(self.proto.counter, 11)
        self.proto.transport.sendto.assert_called_with(ACK + b'\x00\x0b',
                                                       self.addr)

    def test_close_transport_after_file_finished(self):
        data = DAT + b'\x00\x0BAAAA'
        self.proto.datagram_received(data, self.addr)

        self.assertTrue(self.proto.transport.close.called)

    def test_correct_packet_received_and_saved(self):
        data = DAT + b'\x00\x0BAAAA'
        self.proto.datagram_received(data, self.addr)

        self.proto.file_handler.write_chunk.assert_called_with(b'AAAA')

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

    def test_bad_packet_sequence_is_ignored(self):
        data = DAT + b'\x00\x0CAAAA'
        self.proto.datagram_received(data, self.addr)

        self.assertFalse(self.proto.transport.sendto.called)


class TestRRQProtocol(t.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet_factory = TFTPPacketFactory()

    def setUp(self):
        self.addr = ('127.0.0.1', 9999,)
        self.rrq = RRQ + b'\x00filename1\x00octet\x00'
        self.proto = RRQProtocol(self.rrq, MagicMock, self.addr, {})
        self.proto.set_proto_attributes()
        self.proto.h_timeout = MagicMock()
        self.proto.file_handler = MagicMock()
        self.proto.file_handler.read_chunk = MagicMock(return_value=b'AAAA')
        self.proto.counter = 10
        self.proto.transport = MagicMock()

    def test_get_next_chunk_of_data(self):
        rsp = self.proto.next_datagram()

        self.assertEqual(rsp.to_bytes(), DAT + b'\x00\x0aAAAA')

    def test_get_sequence_of_chunks(self):
        ack1 = ACK + b'\x00\x0a'
        ack2 = ACK + b'\x00\x0b'
        dat1 = DAT + b'\x00\x0bAAAA'
        dat2 = DAT + b'\x00\x0cAAAA'

        self.proto.datagram_received(ack1, self.addr)
        self.proto.datagram_received(ack2, self.addr)

        calls = [call(dat1, self.addr), call(dat2, self.addr)]
        self.proto.transport.sendto.assert_has_calls(calls)

    def test_send_last_packet(self):
        self.proto.file_handler.read_chunk = MagicMock(return_value=b'AA')
        self.proto.file_handler.finished = True
        ack1 = ACK + b'\x00\x0a'

        self.proto.datagram_received(ack1, self.addr)

        self.proto.transport.sendto.assert_called_with(DAT + b'\x00\x0bAA',
                                                       self.addr)
        self.assertTrue(self.proto.transport.close.called)

    def test_bad_packet(self):
        bad_msg = DAT + b'\x00\x0aAAAA'

        self.proto.datagram_received(bad_msg, self.addr)

        self.assertFalse(self.proto.transport.sendto.called)

    def test_bad_tid(self):
        # this should get moved to base tests, same for wrq
        addr = ('127.0.0.1', 8888,)
        ack1 = ACK + b'\x00\x0a'

        self.proto.datagram_received(ack1, addr)

        err_tid = self.packet_factory.err_unknown_tid()

        self.proto.transport.sendto.assert_called_with(err_tid.to_bytes(),
                                                       addr)

    def test_bad_packet_sequence_is_ignored(self):
        ack1 = ACK + b'\x00\x0b'

        self.proto.datagram_received(ack1, self.addr)

        self.assertFalse(self.proto.transport.sendto.called)
        self.assertFalse(self.proto.file_iterator.send.called)
