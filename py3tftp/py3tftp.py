import os
import logging
import asyncio
import os.path as opath

from py3tftp.cli_parser import parse_cli_arguments


RRQ = b'\x00\x01'
WRQ = b'\x00\x02'
DAT = b'\x00\x03'
ACK = b'\x00\x04'
ERR = b'\x00\x05'
READSIZE = 512
ACK_TIMEOUT = 0.5
CONN_TIMEOUT = 3.0

# make into module and upload to pypr -> http://python-packaging.readthedocs.org/en/latest/minimal.html
# asyncio file io?


class BaseTFTPProtocol(asyncio.DatagramProtocol):
    def __init__(self, request, remote_addr):
        self.remote_addr = remote_addr
        self.filename, _ = self.validate_req(*self.parse_req(request))
        self.retransmit = None

    def validate_req(self, fname, mode):
        return (fname.decode(encoding='ascii'), mode,)

    def parse_req(self, req):
        logging.debug("Reqest: {}".format(req))
        rq = req.split(b'\x00')
        logging.debug("Parsed request: {}".format(rq))
        return rq[0], rq[1]

    def pack_short(self, number):
        return number.to_bytes(2, byteorder='big')

    def unpack_short(self, data):
        return int.from_bytes(data, byteorder='big')

    def pack_data(self, data, block_no):
        return b''.join((DAT, self.pack_short(block_no), data,))

    def unpack_data(self, data):
        return data[4:]

    def sanitize_fname(self, fname):
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))

    def connection_lost(self, exc):
        self.h_timeout.cancel()
        if exc:
            logging.error("Error on connection lost: {}".format(exc))
        else:
            logging.info("Connection to {0}:{1} terminated".format(
                *self.remote_addr))

    def error_received(self, exc):
        self.h_timeout.cancel()
        self.retransmit_reset()
        self.transport.close()
        logging.error(
            "Error receiving packet from {0}: {1}. Transfer of '{2}' aborted".format(
                self.remote_addr, exc, self.filename))

    def reply_to_client(self, pkt):
        self.transport.sendto(pkt, self.remote_addr)
        self.retransmit = asyncio.get_event_loop().call_later(
            ACK_TIMEOUT, self.reply_to_client, pkt)

    def retransmit_reset(self):
        if self.retransmit:
            self.retransmit.cancel()

    def send_opening_packet(self, packet):
        self.reply_to_client(packet)
        self.h_timeout = asyncio.get_event_loop().call_later(
            CONN_TIMEOUT, self.conn_timeout)

    def conn_timeout(self):
        logging.error(
            "Connection to {0} timed out, '{1}' not transfered".format(
                self.remote_addr, self.filename))
        self.retransmit_reset()
        self.transport.close()

    def conn_timeout_reset(self):
        self.h_timeout.cancel()
        self.h_timeout = asyncio.get_event_loop().call_later(
            CONN_TIMEOUT, self.conn_timeout)

    def err_file_exists(self):
        return ERR + b'\x00\x06File already exists\x00'

    def err_access_violation(self):
        return ERR + b'\x00\x02Access violation\x00'

    def err_file_not_found(self):
        return ERR + b'\x00\x01File not found\x00'

    def err_unknown_tid(self):
        return ERR + b'\x00\x05Unknown transfer id\x00'

    def is_correct_tid(self, addr):
        if self.remote_addr[1] == addr[1]:
            return True
        else:
            logging.warning(
                'Unknown transfer id: expected {0}, got {1} instead.'.format(
                    self.remote_addr, addr))
            self.transport.sendto(self.err_unknown_tid(), addr)
            return False

    def handle_initialization(self):
        try:
            pkt = self.initialize_transfer()
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

        self.send_opening_packet(pkt)

        if pkt[:2] == ERR:
            logging.info(
                "Closing connection to {0} due to error. '{1}' Not transmitted.".format(
                    self.remote_addr, self.filename))
            self.retransmit_reset()
            self.h_timeout.cancel()
            asyncio.get_event_loop().call_soon(self.transport.close)

    def connection_made(self, transport):
        self.transport = transport
        self.handle_initialization()

    def datagram_received(self, data, addr):
        raise NotImplementedError

    def initialize_transfer(self):
        raise NotImplementedError


class WRQProtocol(BaseTFTPProtocol):
    def __init__(self, wrq, addr):
        super().__init__(wrq, addr)
        logging.info(
            "Initiating WRQProtocol, recving file '{0}' from {1}".format(
                self.filename, self.remote_addr))

    def is_data(self, data):
        return data[:2] == DAT

    def is_correct_data(self, data):
        data_no = self.unpack_short(data[2:4])
        return self.counter + 1 == data_no

    def current_ack(self):
        return ACK + self.pack_short(self.counter)

    def initialize_transfer(self):
        self.counter = 0
        self.file_writer = self.get_file_writer(self.filename)
        return self.current_ack()

    def datagram_received(self, data, addr):
        if (self.is_correct_tid(addr) and
                self.is_data(data) and
                self.is_correct_data(data)):
            self.conn_timeout_reset()
            self.retransmit_reset()

            self.counter += 1
            self.reply_to_client(self.current_ack())

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
        fpath = self.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'xb') as f:
                while True:
                    data = yield
                    f.write(data)
                    if len(data) < READSIZE:
                        raise StopIteration
        writer = iterator()
        writer.send(None)
        return writer


class RRQProtocol(BaseTFTPProtocol):
    def __init__(self, rrq, addr):
        super().__init__(rrq, addr)
        logging.info(
            "Initiating RRQProtocol, sending file '{0}' to {1}".format(
                self.filename, self.remote_addr))

    def is_ack(self, data):
        return data[:2] == ACK

    def is_correct_ack(self, data):
        ack_count = self.unpack_short(data[2:4])
        return self.counter == ack_count

    def initialize_transfer(self):
        self.counter = 1
        self.file_reader = self.get_file_reader(self.filename)
        return self.pack_data(next(self.file_reader), self.counter)

    def datagram_received(self, data, addr):
        self.conn_timeout_reset()

        if (self.is_correct_tid(addr) and
                self.is_ack(data) and
                self.is_correct_ack(data)):
            self.retransmit_reset()
            try:
                self.counter += 1
                packet = self.pack_data(next(self.file_reader), self.counter)
                self.reply_to_client(packet)
            except StopIteration:
                logging.info("Sending file '{0}' to {1} completed".format(
                    self.filename, self.remote_addr))
                self.transport.close()
        else:
            logging.debug("ack: {0}; is_ack: {1}; counter: {2}".format(
                data, self.is_ack(data), self.counter))

    def get_file_reader(self, fname):
        fpath = self.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(READSIZE), b''):
                    yield chunk
        return iterator()


class TFTPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop):
        self.loop = loop

    def connection_made(self, transport):
        logging.info("Listening...")
        self.transport = transport

    def datagram_received(self, data, addr):
        logging.debug("received: {}".format(data.decode()))
        tx_type = data[:2]
        chunk = data[2:]

        logging.debug("tx_type: {}".format(tx_type))
        logging.debug("chunk: {}".format(chunk))
        if tx_type == RRQ:
            server = RRQProtocol
        elif tx_type == WRQ:
            server = WRQProtocol
        else:
            logging.error("Received malformed packet")
            return

        connect = self.loop.create_datagram_endpoint(
            lambda: server(chunk, addr),
            local_addr=('127.0.0.1', 0,))

        self.loop.create_task(connect)

    def connection_lost(self, exc):
        logging.info('TFTP server - connection lost')

if __name__ == '__main__':
    args = parse_cli_arguments()

    logging.info('Starting TFTP server on {addr}:{port}'.format(
        addr=args.host, port=args.port))
    loop = asyncio.get_event_loop()
    listen = loop.create_datagram_endpoint(
        lambda: TFTPServerProtocol(loop),
        local_addr=(args.host, args.port,))

    transport, protocol = loop.run_until_complete(listen)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info('Received signal, shutting down')

    transport.close()
    loop.close()
