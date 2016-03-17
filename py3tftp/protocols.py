from typing import Dict, Tuple, Optional, Any, Union, Iterator
import logging
import asyncio

from .exceptions import ProtocolException
from .opt_parsers import TFTPOptParserMixin, blksize_parser, timeout_parser

RRQ = b'\x00\x01'
WRQ = b'\x00\x02'
DAT = b'\x00\x03'
ACK = b'\x00\x04'
ERR = b'\x00\x05'
OCK = b'\x00\x06'


class BaseTFTPProtocol(asyncio.DatagramProtocol, TFTPOptParserMixin):
    supported_opts = {
         b'blksize': blksize_parser,
         b'timeout': timeout_parser,
    }

    default_opts = {
        b'ack_timeout': 0.5,
        b'timeout': 5.0,
        b'blksize': 512
    }

    def __init__(self, request: bytes,
                 remote_addr: Tuple[str, int],
                 extra_opts: Optional[Dict[str, Any]] = None) -> None:
        self.remote_addr = remote_addr
        self.request = request
        self.extra_opts = extra_opts
        if not self.extra_opts:
            self.extra_opts = {}
        self.retransmit = None
        self.file_iterator = None
        self.finished = False

    def datagram_received(self,
                          data: bytes,
                          addr: Tuple[str, int]) -> None:
        """
        Processes every received datagram.
        """
        raise NotImplementedError

    def initialize_transfer(self) -> None:
        """
        Sets up the message counter and attempts to open the target file for
        reading or writing.
        """
        raise NotImplementedError

    def next_datagram(self) -> bytes:
        """
        Returns the next datagram to be sent to self.remote_addr.
        """
        raise NotImplementedError

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """
        Triggers connection initialization at the beginning of a connection.
        """
        self.transport = transport
        self.handle_initialization()

    def handle_initialization(self) -> None:
        """
        Sends first packet to self.remote_addr. In the process, it attempts to
        access the requested file - and handles possible file errors - as well
        as handling option negotiation (if applicable).
        """
        try:
            self.set_proto_attributes()
            self.initialize_transfer()

            if self.r_opts:
                self.counter = 0 # type: int
                pkt = self.oack_packet()
            else:
                pkt = self.next_datagram()
        except FileExistsError:
            logging.error('"{}" already exists! Cannot overwrite'.format(
                self.filename))
            pkt = self.err_file_exists()
        except PermissionError:
            logging.error('Insufficient permissions to operate on "{}"'.format(
                self.filename))
            pkt = self.err_access_violation()
        except FileNotFoundError:
            logging.error('File "{}" does not exist!'.format(self.filename))
            pkt = self.err_file_not_found()

        logging.debug('opening pkt: {}'.format(pkt))
        self.send_opening_packet(pkt)

        if self.is_err(pkt):
            self.handle_err_pkt()

    def set_proto_attributes(self) -> None:
        """
        Sets the self.filename , self.opts, and self.r_opts.
        The caller should handle any exceptions and react accordingly
        ie. send error packet, close connection, etc.
        """
        self.filename, _, self.r_opts = self.validate_req(
            *self.parse_req(self.request))
        logging.debug(self.r_opts)
        self.opts = {**self.default_opts, **self.extra_opts, **self.r_opts}
        logging.debug(self.opts)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """
        Cleans up socket and fd after connection has been lost. Logs an error
        if connection interrupted.
        """
        self.conn_reset()
        if self.file_iterator:
            self.file_iterator.close()
        if exc:
            logging.error(
                'Error on connection lost: {0}.\nTraceback: {1}'.format(
                    exc, exc.__traceback__))
        else:
            logging.info('Connection to {0}:{1} terminated'.format(
                *self.remote_addr))

    def error_received(self, exc: Optional[Exception]) -> None:
        """
        Handles cleanup after socket reports an error ie. local or remote
        socket closed and other network errors.
        """

        self.conn_reset()
        self.transport.close()
        logging.error((
            'Error receiving packet from {0}: {1}. '
            'Transfer of "{2}" aborted.\nTraceback: {3}').format(
                self.remote_addr, exc, self.filename, exc.__traceback__))

    def send_opening_packet(self, packet: bytes) -> None:
        """
        Starts the connection timeout timer and sends first datagram.
        """
        self.reply_to_client(packet)
        self.h_timeout = asyncio.get_event_loop().call_later(
            self.opts['timeout'], self.conn_timeout)

    def reply_to_client(self, packet: bytes) -> None:
        """
        Starts the message retry loop, resending packet to self.remote_addr
        every 'ack_timeout'.
        """
        self.transport.sendto(packet, self.remote_addr)
        self.retransmit = asyncio.get_event_loop().call_later(
            self.opts['ack_timeout'], self.reply_to_client, packet)

    def handle_err_pkt(self) -> None:
        """
        Cleans up connection after sending a courtesy error packet
        to offending client.
        """
        logging.info((
            'Closing connection to {0} due to error. '
            '"{1}" Not transmitted.').format(
                self.remote_addr, self.filename))
        self.conn_reset()
        asyncio.get_event_loop().call_soon(self.transport.close)

    def retransmit_reset(self) -> None:
        """
        Stops the message retry loop.
        """
        if self.retransmit:
            self.retransmit.cancel()

    def conn_reset(self) -> None:
        """
        Stops the message retry loop and the connection timeout timers.
        """
        self.retransmit_reset()
        if self.h_timeout:
            self.h_timeout.cancel()

    def conn_timeout(self) -> None:
        """
        Cleans up timers and the connection when called.
        """

        logging.error(
            'Connection to {0} timed out, "{1}" not transfered'.format(
                self.remote_addr, self.filename))
        self.retransmit_reset()
        self.transport.close()

    def conn_timeout_reset(self) -> None:
        """
        Restarts the connection timeout timer.
        """

        self.conn_reset()
        self.h_timeout = asyncio.get_event_loop().call_later(
            self.opts['timeout'], self.conn_timeout)

    def oack_packet(self) -> bytes:
        """
        Builds a OACK response that contains accepted options.
        """

        options = b'\x00'.join(
            b'\x00'.join(
                (k, v if isinstance(v, bytes) else self.number_to_bytes(v)))
            for k, v in self.r_opts.items())

        return OCK + options + b'\x00'

    def number_to_bytes(self, val: Union[int, float]) -> bytes:
        """
        Changes a number to an ascii byte string.
        """
        return bytes(str(int(val)), encoding='ascii')

    def is_err(self, pkt: bytes) -> bool:
        return pkt[:2] == ERR

    def is_correct_tid(self, addr: Tuple[str, int]) -> bool:
        """
        Checks whether address '(ip, port)' matches that of the
        established remote host.
        May send error to host that submitted incorrect address.
        """
        if self.remote_addr[1] == addr[1]:
            return True
        else:
            logging.warning(
                'Unknown transfer id: expected {0}, got {1} instead.'.format(
                    self.remote_addr, addr))
            self.transport.sendto(self.err_unknown_tid(), addr)
            return False

    def pack_short(self, number: int) -> bytes:
        """
        Create big-endian short byte string out of integer.
        """
        return number.to_bytes(2, byteorder='big')

    def unpack_short(self, data: bytes) -> int:
        """
        Create integer out of big-endian short byte string.
        """
        return int.from_bytes(data, byteorder='big')

    def pack_data(self, data: bytes = b'', block_no: int = 0) -> bytes:
        """
        Builds a data packet.
        """
        return b''.join((DAT, self.pack_short(block_no), data,))

    def unpack_data(self, data: bytes) -> bytes:
        """
        Skips message header, return just the message.
        """
        return data[4:]

    def err_file_exists(self) -> bytes:
        return ERR + b'\x00\x06File already exists\x00'

    def err_access_violation(self) -> bytes:
        return ERR + b'\x00\x02Access violation\x00'

    def err_file_not_found(self) -> bytes:
        return ERR + b'\x00\x01File not found\x00'

    def err_unknown_tid(self) -> bytes:
        return ERR + b'\x00\x05Unknown transfer id\x00'


class WRQProtocol(BaseTFTPProtocol):
    def __init__(self, wrq: bytes, addr: Tuple[str, int],
                 opts: Dict[str, Any]) -> None:
        super().__init__(wrq, addr, opts)
        logging.info('Initiating WRQProtocol with {0}'.format(
            self.remote_addr))

    def is_data(self, data: bytes) -> bool:
        return data[:2] == DAT

    def is_correct_data(self, data: bytes) -> bool:
        """
        Checks whether incoming data packet has the expected block number.
        """
        data_no = self.unpack_short(data[2:4])
        return self.counter + 1 == data_no

    def next_datagram(self) -> bytes:
        """
        Builds an acknowledgement of a received data packet.
        """
        return ACK + self.pack_short(self.counter)

    def initialize_transfer(self) -> None:
        self.counter = 0
        self.file_iterator = self.get_file_writer(self.filename)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Check correctness of received datagram, reset timers, increment
        counter, ACKnowledge datagram, save received data to file.
        """
        if (self.is_correct_tid(addr) and
                self.is_data(data) and
                self.is_correct_data(data)):
            self.conn_timeout_reset()

            self.counter += 1
            self.reply_to_client(self.next_datagram())

            try:
                self.file_iterator.send(self.unpack_data(data))
            except StopIteration:
                logging.info('Receiving file "{0}" from {1} completed'.format(
                    self.filename, self.remote_addr))
                self.retransmit_reset()
                self.transport.close()
        else:
            logging.debug('Data: {0}; is_data: {1}; counter: {2}'.format(
                data, self.is_data(data), self.counter))

    def get_file_writer(self, fname: bytes) -> Iterator:
        """
        Returns an iterator function to read a file in blksize blocks.
        """
        fpath = self.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'xb') as f:
                while True:
                    data = yield
                    f.write(data)
                    if len(data) < self.opts[b'blksize']:
                        raise StopIteration
        writer = iterator()
        writer.send(None)
        return writer


class RRQProtocol(BaseTFTPProtocol):
    def __init__(self,
                 rrq: bytes,
                 addr: Tuple[str, int],
                 opts: Dict[str, Any]) -> None:
        super().__init__(rrq, addr, opts)
        logging.info('Initiating RRQProtocol with {0}'.format(
            self.remote_addr))

    def is_ack(self, data: bytes) -> bool:
        return data[:2] == ACK

    def is_correct_ack(self, data: bytes) -> bool:
        """
        Checks if ACK is correct in sequence.
        """
        ack_count = self.unpack_short(data[2:4])
        return self.counter == ack_count

    def next_datagram(self) -> bytes:
        return self.pack_data(next(self.file_iterator), self.counter)

    def initialize_transfer(self) -> None:
        self.counter = 1
        self.file_iterator = self.get_file_reader(self.filename)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Checks correctness of incoming datagrams, reset timers,
        increments message counter, send next chunk of requested file
        to client.
        """
        if (self.is_correct_tid(addr) and
                self.is_ack(data) and
                self.is_correct_ack(data)):
            self.conn_timeout_reset()
            try:
                self.counter += 1
                packet = self.next_datagram()
                self.reply_to_client(packet)
                if len(packet) < self.opts[b'blksize']:
                    self.finished = True
            except StopIteration:
                logging.info('Sending file "{0}" to {1} completed'.format(
                    self.filename, self.remote_addr))
                if not self.finished:
                    last_dat = self.pack_data(block_no=self.counter)
                    self.reply_to_client(last_dat)
                self.transport.close()
        else:
            logging.debug('Ack: {0}; is_ack: {1}; counter: {2}'.format(
                data, self.is_ack(data), self.counter))

    def get_file_reader(self, fname: bytes) -> Iterator:
        """
        Returns an iterator of a file, read in blksize chunks.
        """
        fpath = self.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(self.opts[b'blksize']), b''):
                    yield chunk
        return iterator()


class BaseTFTPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self,
                 host_interface: str,
                 loop: asyncio.BaseEventLoop,
                 extra_opts: Dict[str, Any]) -> None:
        self.host_interface = host_interface
        self.loop = loop
        self.extra_opts = extra_opts

    def select_protocol(self,
                        request: bytes,
                        remote_addr: Tuple[str, int]) -> BaseTFTPProtocol:
        """
        Selects an asyncio.Protocol-compatible protocol to
        feed to an event loop's 'create_datagram_endpoint'
        function.
        """
        raise NotImplementedError

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        logging.info('Listening...')
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Opens a read or write connection to remote host by scheduling
        an asyncio.Protocol.
        """
        logging.debug('received: {}'.format(data.decode()))

        protocol = self.select_protocol(data, addr)

        chunk = data[2:]
        logging.debug('chunk: {}'.format(chunk))

        connect = self.loop.create_datagram_endpoint(
            lambda: protocol(chunk, addr, self.extra_opts),
            local_addr=(self.host_interface, 0,))

        self.loop.create_task(connect)

    def connection_lost(self, exc: Exception):
        logging.info('TFTP server - connection lost')


class TFTPServerProtocol(BaseTFTPServerProtocol):
    def select_protocol(self,
                        req: bytes,
                        remote_addr: Tuple[str, int]) -> BaseTFTPProtocol:
        tx_type = req[:2]
        logging.debug('tx_type: {}'.format(tx_type))
        if tx_type == RRQ:
            return RRQProtocol
        elif tx_type == WRQ:
            return WRQProtocol
        else:
            raise ProtocolException('Received incompatible request, ignoring.')
