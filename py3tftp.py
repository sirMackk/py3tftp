import os
import logging
import asyncio
import os.path as opath


RRQ = b'\x01\x00'
WRQ = b'\x02\x00'
DAT = b'\x03\x00'
ACK = b'\x04\x00'
ERR = b'\x05\x00'
READSIZE = 512
ACK_TIMEOUT = 0.5
CONN_TIMEOUT = 3.0

# test various exceptional situations
# send err packets when required
# asyncio file io?


class SafeOpen(object):
    def __init__(self, fname, mode):
        self.fname = fname
        self.mode = mode

    def __enter__(self):
        try:
            self.file = open(self.fname, self.mode)
        except FileExistsError:
            logging.error("{} already exists! Cannot overwrite".format(
                self.fname))
        except PermissionError:
            logging.error("Insufficient permissions to operate on {}".format(
                self.fname))
        except FileNotFoundError:
            logging.error("{} does not exist!".format(self.fname))
        return self.file

    def __exit__(self, *exc):
        self.file.close()


class BaseTftpServer(object):
    def __init__(self, request, remote_addr):
        self.remote_addr = remote_addr
        self.filename, _ = self.validate_req(*self.parse_req(request))

    def validate_req(self, fname, mode):
        return (fname.decode(encoding='ascii'), mode,)

    def parse_req(self, req):
        logging.debug("Reqest: {}".format(req))
        rq = req.split(b'\x00')
        logging.debug("Parsed request: {}".format(rq))
        return rq[0], rq[1]

    def pack_short(self, number):
        return number.to_bytes(2, byteorder='little')

    def unpack_short(self, data):
        return int.from_bytes(data, byteorder='little')

    def sanitize_fname(self, fname):
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))

    def connection_lost(self, exc):
        self.h_timeout.cancel()
        logging.info("Connection to {0}:{1} terminated".format(
            *self.remote_addr))
        if exc:
            logging.error(exc)

    def error_received(self, exc):
        self.h_timeout.cancel()
        self.retransmit.cancel()
        logging.error("Error receiving packet from {0}: {1}".format(
            self.remote_addr, exc))

    def reply_to_client(self, pkt):
        self.transport.sendto(pkt)
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
        logging.error("Connection to {} timed out".format(self.remote_addr))
        self.retransmit.cancel()
        self.transport.close()

    def conn_timeout_reset(self):
        self.h_timeout.cancel()
        self.h_timeout = asyncio.get_event_loop().call_later(
            CONN_TIMEOUT, self.conn_timeout)

    def connection_made(self, transport):
        raise NotImplementedError

    def datagram_received(self, data, addr):
        raise NotImplementedError


class WRQServer(BaseTftpServer):
    def __init__(self, wrq, addr):
        logging.info("Starting WRQServer, recving file from {}".format(
            addr))
        super().__init__(wrq, addr)

    def is_data(self, data):
        return data[:2] == DAT

    def is_correct_data(self, data):
        data_no = self.unpack_short(data[2:4])
        return self.counter + 1 == data_no

    def current_ack(self):
        return ACK + self.pack_short(self.counter)

    def connection_made(self, transport):
        self.transport = transport
        self.counter = 0
        self.file_writer = self.get_file_writer(self.filename)
        pkt = self.current_ack()
        self.send_opening_packet(pkt)

    def datagram_received(self, data, addr):
        if self.is_data(data) and self.is_correct_data(data):
            self.conn_timeout_reset()
            self.retransmit_reset()

            self.counter += 1
            self.reply_to_client(self.current_ack())
            try:
                self.file_writer.send(data[4:])
            except StopIteration:
                logging.info("Receiving file from {} completed".format(
                    self.remote_addr))
                self.retransmit.cancel()
                self.transport.close()
        else:
            logging.debug("data: {0}; is_data: {1}; counter: {2}".format(
                data, self.is_data(data), self.counter))

    def get_file_writer(self, fname):
        fpath = self.sanitize_fname(fname)

        def iterator():
            with SafeOpen(fpath, 'xb') as f:
                while True:
                    data = yield
                    f.write(data)
                    if len(data) < READSIZE:
                        raise StopIteration
        writer = iterator()
        writer.send(None)
        return writer


class RRQServer(BaseTftpServer):
    def __init__(self, rrq, addr):
        logging.info("Starting RRQServer, sending file to {}".format(
            addr))
        super().__init__(rrq, addr)

    def is_ack(self, data):
        return data[:2] == ACK

    def correct_ack(self, data):
        ack_count = self.unpack_short(data[2:4])
        return self.counter == ack_count

    def connection_made(self, transport):
        self.transport = transport
        self.counter = 1
        self.file_reader = self.get_file_reader(self.filename)
        pkt = next(self.file_reader)
        self.send_opening_packet(pkt)

    def datagram_received(self, data, addr):
        self.conn_timeout_reset()

        if self.is_ack(data) and self.correct_ack(data):
            self.retransmit_reset()
            try:
                self.counter += 1
                packet = next(self.file_reader)
                self.reply_to_client(packet)
            except StopIteration:
                logging.info("Sending file to {} completed".format(
                    self.remote_addr))
                self.transport.close()
        else:
            logging.debug("ack: {0}; is_ack: {1}; counter: {2}".format(
                data, self.is_ack(data), self.counter))

    def get_file_reader(self, fname):
        fpath = self.sanitize_fname(fname)

        def iterator():
            with SafeOpen(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(READSIZE), b''):
                    yield chunk
        return iterator()


class TftpServer(object):
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
            server = RRQServer
        elif tx_type == WRQ:
            server = WRQServer
        else:
            logging.error("Received malformed packet")
            raise Exception("WUT")
        connect = loop.create_datagram_endpoint(
            lambda: server(chunk, addr),
            remote_addr=addr)

        self.loop.create_task(connect)

    def connection_lost(self, exc):
        logging.info('TFTP server - connection lost')

if __name__ == '__main__':
    # argparse
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s',
        level=logging.INFO)
    port = 8069
    i_addr = '127.0.0.1'

    logging.info('Starting TFTP server on {i_addr}:{port}'.format(
        i_addr=i_addr, port=port))
    loop = asyncio.get_event_loop()
    listen = loop.create_datagram_endpoint(
        lambda: TftpServer(loop),
        local_addr=(i_addr, port,))

    transport, protocol = loop.run_until_complete(listen)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info('Received signal, shutting down')

    transport.close()
    loop.close()
