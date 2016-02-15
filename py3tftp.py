import os
import logging
import asyncio
from struct import Struct
import os.path as opath


RRQ = b'\x01\x00'
WRQ = b'\x02\x00'
DAT = b'\x03\x00'
ACK = b'\x04\x00'
ERR = b'\x05\x00'
READSIZE = 512
TWOBYTE = Struct('=H')

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.DEBUG)


def byte_packer(length):
    return Struct('={length}H'.format(length=length))


class WRQServer(object):
    pass


class RRQServer(object):
    # add timeouts
    def __init__(self, rrq, addr):
        logging.info("Starting RRQServer, sending file to {}".format(
            addr))
        self.addr = addr
        filename, _ = self.validate_req(*self.parse_req(rrq))
        self.file_iterator = self.get_file_iterator(filename)
        self.counter = 1
        self.short_int = byte_packer(1)

    def validate_req(self, fname, mode):
        # validate format and opts
        return (fname.decode(encoding='ascii'), mode,)

    def parse_req(self, req):
        logging.debug("Reqest: {}".format(req))
        rq = req.split(b'\x00')
        logging.debug("Parsed request: {}".format(rq))
        return rq[0], rq[1]

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(next(self.file_iterator))

    def datagram_received(self, data, addr):
        logging.debug("Receiving dgram, length: {}".format(len(data)))
        if self.is_ack(data) and self.correct_ack(data):
            try:
                self.counter += 1
                logging.debug("sending!")
                self.transport.sendto(next(self.file_iterator))
            except StopIteration:
                self.info("File transfer complete")
                self.transport.close()
        else:
            logging.debug("is_ack? {}".format(self.is_ack(data)))
            logging.debug("correct_ack? {}".format(self.correct_ack(data)))

    def error_received(self, exc):
        logging.error("Error receiving packet: {}".format(exc))

    def is_ack(self, data):
        return data[:2] == ACK

    def correct_ack(self, data):
        ack_count, = self.short_int.unpack(data[2:4])
        return self.counter == ack_count

    def next_data_pkt(self):
        pkt = b''.join(DAT,
                       self.short_int.pack(self.counter),
                       next(self.file_iterator()))
        return pkt

    def sanitize_fname(self, fname):
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))

    def get_file_iterator(self, fname):
        fpath = self.sanitize_fname(fname)
        # nice to separate into reader/writer with partial func-like

        def iterator():
            try:
                # xb
                # rb
                with open(fpath, 'rb') as f:
                    while True:
                        contents = f.read(READSIZE)
                        if not contents:
                            break
                        yield contents
            except FileExistsError:
                logging.error("{} already exists! Cannot overwrite".format(
                    fpath))
            except PermissionError:
                logging.error("Insufficient permissions to read {}".format(
                    fpath))
            except FileNotFoundError:
                logging.error("{} does not exist!".format(fpath))
        return iterator()

    def connection_lost(self, exc):
        logging.info("Connection to {0}:{1} terminated".format(*self.addr))
        # might remove
        logging.info(exc)


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
        log.info('Received signal, shutting down')

    transport.close()
    loop.close()
