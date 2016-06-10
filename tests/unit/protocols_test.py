import unittest as t
from unittest.mock import MagicMock

from py3tftp.protocols import (
    TFTPServerProtocol, RRQProtocol, WRQProtocol)

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
