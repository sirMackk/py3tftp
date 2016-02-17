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

    def pack_short_int(self, number):
        return number.to_bytes(2, byteorder='little')

    def unpack_short_int(self, data):
        return int.from_bytes(data, byteorder='little')

    def is_ack(self, data):
        return data[:2] == ACK

    def correct_ack(self, data):
        ack_count = self.unpack_short_int(data[2:4])
        return self.counter == ack_count

    def sanitize_fname(self, fname):
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))

    def connection_lost(self, exc):
        self.h_timeout.cancel()
        logging.info("Connection to {0}:{1} terminated".format(*self.remote_addr))
        # might remove
        logging.info(exc)

    def error_received(self, exc):
        self.h_timeout.cancel()
        self.retransmit.cancel()
        logging.error("Error receiving packet from {0}: {1}".format(self.remote_addr,
                                                                    exc))

    def transmit(self, pkt):
        self.transport.sendto(pkt)
        self.retransmit = asyncio.get_event_loop().call_later(
            ACK_TIMEOUT, self.transmit, pkt)

    def opening_packet(self, packet):
        self.transmit(packet)
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

    def datagram_received(self, data, addr):
        raise NotImplementedError

    def connection_made(self, transport):
        raise NotImplementedError


class WRQServer(object):
    pass
    # def get_file_writer(self, fname):
        # except FileExistsError:
            # logging.error("{} already exists! Cannot overwrite".format(
                # fpath))
        # except PermissionError:
            # logging.error("Insufficient permissions to read {}".format(
                # fpath))
        # # xb


class RRQServer(BaseTftpServer):
    def __init__(self, rrq, addr):
        logging.info("Starting RRQServer, sending file to {}".format(
            addr))
        super().__init__(rrq, addr)

    def connection_made(self, transport):
        self.counter = 1
        self.file_reader = self.get_file_reader(self.filename)
        self.transport = transport
        packet = next(self.file_reader)
        self.opening_packet(packet)


    def datagram_received(self, data, addr):
        self.conn_timeout_reset()

        logging.debug("Receiving dgram, length: {}".format(len(data)))
        if self.is_ack(data) and self.correct_ack(data):
            if self.retransmit:
                self.retransmit.cancel()
            try:
                self.counter += 1
                logging.debug("sending!")
                packet = next(self.file_reader)
                self.transmit(packet)
            except StopIteration:
                logging.info("File transfer complete")
                self.transport.close()
        else:
            logging.debug("ack: {0}; is_ack: {1}; counter: {2}".format(
                data, self.is_ack(data), self.counter))

    def get_file_reader(self, fname):
        fpath = self.sanitize_fname(fname)

        def iterator():
            try:
                with open(fpath, 'rb') as f:
                    for chunk in iter(lambda: f.read(READSIZE), b''):
                        yield chunk
            except PermissionError:
                logging.error("Insufficient permissions to read {}".format(
                    fpath))
            except FileNotFoundError:
                logging.error("{} does not exist!".format(fpath))
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
