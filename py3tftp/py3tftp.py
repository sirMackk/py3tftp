import os
import logging
import asyncio
import os.path as opath

__version__ = '0.0.2'


RRQ = b'\x00\x01'
WRQ = b'\x00\x02'
DAT = b'\x00\x03'
ACK = b'\x00\x04'
ERR = b'\x00\x05'
OCK = b'\x00\x06'


class TFTPOptParserMixin(object):
    def validate_req(self, fname, mode, opts):
        """
        Filters 'opts' to get rid of options absent from self.supported_opts
        and casts the filtered options to expected types.
        """
        options = {}
        for option, value in opts.items():
            logging.debug(option)
            if option in self.supported_opts.keys():
                logging.debug(option)
                options[option] = self.supported_opts[option](value)

        return (fname.decode(encoding='ascii'), mode, options)

    def parse_req(self, req):
        """
        Seperates \x00 delimited byte string contents according to RFC1350:
        'filename\x00mode\x00opt1\x00val1\x00optN\x00valN\x00' into a
        filename, a mode, and a dictionary of option:values.
        """
        logging.debug("Reqest: {}".format(req))
        fname, mode, *opts = filter(None, req.split(b'\x00'))
        options = dict(zip(opts[::2], opts[1::2]))
        return fname, mode, options

    def sanitize_fname(self, fname):
        """
        Ensures that fname is a path under the current working directory.
        """
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))


class BaseTFTPProtocol(asyncio.DatagramProtocol, TFTPOptParserMixin):
    supported_opts = {
         b'blksize': int,
         b'timeout': float,
    }

    default_opts = {
        b'ack_timeout': 0.5,
        b'timeout': 5.0,
        b'blksize': 512
    }

    def __init__(self, request, remote_addr, timeout_opts):
        self.remote_addr = remote_addr
        self.filename, _, self.r_opts = self.validate_req(
            *self.parse_req(request))
        logging.debug(self.r_opts)
        self.opts = {**self.default_opts, **timeout_opts, **self.r_opts}
        logging.debug(self.opts)
        self.retransmit = None

    def datagram_received(self, data, addr):
        """
        Processes every received datagram.
        """
        raise NotImplementedError

    def initialize_transfer(self):
        """
        Sets up the message counter and attempts to open the target file for
        reading or writing.
        """
        raise NotImplementedError

    def next_datagram(self):
        """
        Returns the next datagram to be sent to self.remote_addr.
        """
        raise NotImplementedError

    def connection_made(self, transport):
        """
        Triggers connection initialization at the beginning of a connection.
        """
        self.transport = transport
        self.handle_initialization()

    def handle_initialization(self):
        """
        Sends first packet to self.remote_addr. In the process, it attempts to
        access the requested file - and handles possible file errors - as well
        as handling option negotiation (if applicable).
        """
        try:
            self.initialize_transfer()
            if self.r_opts:
                self.counter = 0
                pkt = self.oack_packet()
            else:
                pkt = self.next_datagram()
        except FileExistsError:
            logging.error("'{}' already exists! Cannot overwrite".format(
                self.filename))
            pkt = self.err_file_exists()
        except PermissionError:
            logging.error("Insufficient permissions to operate on '{}'".format(
                self.filename))
            pkt = self.err_access_violation()
        except FileNotFoundError:
            logging.error("File '{}' does not exist!".format(self.filename))
            pkt = self.err_file_not_found()

        logging.debug('opening pkt: {}'.format(pkt))
        self.send_opening_packet(pkt)

        if self.is_err(pkt):
            self.handle_err_pkt()

    def connection_lost(self, exc):
        """
        Handles cleanup after connection has been lost. Logs an error
        if connection interrupted.
        """
        self.conn_reset()
        if exc:
            logging.error(
                "Error on connection lost: {0}.\nTraceback: {1}".format(
                    exc, exc.__traceback__))
        else:
            logging.info("Connection to {0}:{1} terminated".format(
                *self.remote_addr))

    def error_received(self, exc):
        """
        Handles cleanup after socket reports an error ie. local or remote
        socket closed and other network errors.
        """

        self.conn_reset()
        self.transport.close()
        logging.error((
            "Error receiving packet from {0}: {1}. "
            "Transfer of '{2}' aborted.\nTraceback: {3}").format(
                self.remote_addr, exc, self.filename, exc.__traceback__))

    def send_opening_packet(self, packet):
        """
        Starts the connection timeout timer and sends first datagram.
        """
        self.reply_to_client(packet)
        self.h_timeout = asyncio.get_event_loop().call_later(
            self.opts['timeout'], self.conn_timeout)

    def reply_to_client(self, pkt):
        """
        Starts the message retry loop, resending pkt to self.remote_addr
        every 'ack_timeout'.
        """
        self.transport.sendto(pkt, self.remote_addr)
        self.retransmit = asyncio.get_event_loop().call_later(
            self.opts['ack_timeout'], self.reply_to_client, pkt)

    def handle_err_pkt(self):
        """
        Cleans up connection after sending a courtesy error packet
        to offending client.
        """
        logging.info((
            "Closing connection to {0} due to error. "
            "'{1}' Not transmitted.").format(
                self.remote_addr, self.filename))
        self.conn_reset()
        asyncio.get_event_loop().call_soon(self.transport.close)

    def retransmit_reset(self):
        """
        Stops the message retry loop.
        """
        if self.retransmit:
            self.retransmit.cancel()

    def conn_reset(self):
        """
        Stops the message retry loop and the connection timeout timers.
        """
        self.retransmit_reset()
        if self.h_timeout:
            self.h_timeout.cancel()

    def conn_timeout(self):
        """
        Cleans up timers and the connection when called.
        """

        logging.error(
            "Connection to {0} timed out, '{1}' not transfered".format(
                self.remote_addr, self.filename))
        self.retransmit_reset()
        self.transport.close()

    def conn_timeout_reset(self):
        """
        Restarts the connection timeout timer.
        """

        self.conn_reset()
        self.h_timeout = asyncio.get_event_loop().call_later(
            self.opts['timeout'], self.conn_timeout)

    def oack_packet(self):
        """
        Builds a OACK response that contains accepted options.
        """
        return (OCK +
                b''.join(b'\x00'.join([k, bytes(str(int(v)), encoding='ascii')])
                         for k, v in self.r_opts.items()) +
                b'\x00')

    def is_err(self, pkt):
        return pkt[:2] == ERR

    def is_correct_tid(self, addr):
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

    def pack_short(self, number):
        """
        Create big-endian short byte string out of integer.
        """
        return number.to_bytes(2, byteorder='big')

    def unpack_short(self, data):
        """
        Create integer out of big-endian short byte string.
        """
        return int.from_bytes(data, byteorder='big')

    def pack_data(self, data, block_no):
        """
        Builds a data packet.
        """
        return b''.join((DAT, self.pack_short(block_no), data,))

    def unpack_data(self, data):
        """
        Skips message header, return just the message.
        """
        return data[4:]

    def err_file_exists(self):
        return ERR + b'\x00\x06File already exists\x00'

    def err_access_violation(self):
        return ERR + b'\x00\x02Access violation\x00'

    def err_file_not_found(self):
        return ERR + b'\x00\x01File not found\x00'

    def err_unknown_tid(self):
        return ERR + b'\x00\x05Unknown transfer id\x00'


class WRQProtocol(BaseTFTPProtocol):
    def __init__(self, wrq, addr, *args):
        super().__init__(wrq, addr, *args)
        logging.info(
            "Initiating WRQProtocol, recving file '{0}' from {1}".format(
                self.filename, self.remote_addr))

    def is_data(self, data):
        return data[:2] == DAT

    def is_correct_data(self, data):
        """
        Checks whether incoming data packet has the expected block number.
        """
        data_no = self.unpack_short(data[2:4])
        return self.counter + 1 == data_no

    def next_datagram(self):
        """
        Builds an acknowledgement of a received data packet.
        """
        return ACK + self.pack_short(self.counter)

    def initialize_transfer(self):
        self.counter = 0
        self.file_writer = self.get_file_writer(self.filename)

    def datagram_received(self, data, addr):
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
                self.file_writer.send(self.unpack_data(data))
            except StopIteration:
                logging.info("Receiving file '{0}' from {1} completed".format(
                    self.filename, self.remote_addr))
                self.retransmit_reset()
                self.transport.close()
        else:
            logging.debug("data: {0}; is_data: {1}; counter: {2}".format(
                data, self.is_data(data), self.counter))

    def get_file_writer(self, fname):
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
    def __init__(self, rrq, addr, *args):
        super().__init__(rrq, addr, *args)
        logging.info(
            "Initiating RRQProtocol, sending file '{0}' to {1}".format(
                self.filename, self.remote_addr))

    def is_ack(self, data):
        return data[:2] == ACK

    def is_correct_ack(self, data):
        """
        Checks if ACK is correct in sequence.
        """
        ack_count = self.unpack_short(data[2:4])
        return self.counter == ack_count

    def next_datagram(self):
        return self.pack_data(next(self.file_reader), self.counter)

    def initialize_transfer(self):
        self.counter = 1
        self.file_reader = self.get_file_reader(self.filename)

    def datagram_received(self, data, addr):
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
            except StopIteration:
                logging.info("Sending file '{0}' to {1} completed".format(
                    self.filename, self.remote_addr))
                self.transport.close()
        else:
            logging.debug("ack: {0}; is_ack: {1}; counter: {2}".format(
                data, self.is_ack(data), self.counter))

    def get_file_reader(self, fname):
        """
        Returns an iterator of a file, read in blksize chunks.
        """
        fpath = self.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(self.opts[b'blksize']), b''):
                    yield chunk
        return iterator()


class TFTPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, host_if, loop, timeout_opts):
        self.host_if = host_if
        self.loop = loop
        self.timeout_opts = timeout_opts

    def connection_made(self, transport):
        logging.info("Listening...")
        self.transport = transport

    def datagram_received(self, data, addr):
        """
        Opens a read or write connection to remote host by scheduling
        an asyncio.Protocol.
        """
        logging.debug("received: {}".format(data.decode()))
        tx_type = data[:2]
        chunk = data[2:]

        logging.debug("tx_type: {}".format(tx_type))
        logging.debug("chunk: {}".format(chunk))
        if tx_type == RRQ:
            proto = RRQProtocol
        elif tx_type == WRQ:
            proto = WRQProtocol
        else:
            logging.error("Received malformed packet")
            return

        connect = self.loop.create_datagram_endpoint(
            lambda: proto(chunk, addr, self.timeout_opts),
            local_addr=(self.host_if, 0,))

        self.loop.create_task(connect)

    def connection_lost(self, exc):
        logging.info('TFTP server - connection lost')


def main():
    from py3tftp.cli_parser import parse_cli_arguments
    args = parse_cli_arguments()

    logging.info('Starting TFTP server on {addr}:{port}'.format(
        addr=args.host, port=args.port))

    timeouts = {k: v for k, v in vars(args).items() if 'timeout' in k}
    loop = asyncio.get_event_loop()
    listen = loop.create_datagram_endpoint(
        lambda: TFTPServerProtocol(args.host, loop, timeouts),
        local_addr=(args.host, args.port,))

    transport, protocol = loop.run_until_complete(listen)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info('Received signal, shutting down')

    transport.close()
    loop.close()

if __name__ == '__main__':
    main()
