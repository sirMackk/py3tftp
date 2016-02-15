import asyncio
from struct import Struct

RRQ = b'\x01\x00'
WRQ = b'\x02\x00'
DAT = b'\x03\x00'
ACK = b'\x04\x00'
ERR = b'\x05\x00'
READSIZE = 512
TWOBYTE = Struct('=H')


def byte_packer(length):
    return Struct('={length}H'.format(length=length))


class WRQServer(object):
    pass


class RRQServer(object):
    # add timeouts
    def __init__(self, rrq, addr):
        print("creating rrq on {}".format(addr))
        self.addr = addr
        filename, _ = self.validate_req(*self.parse_req(rrq))
        self.file_iterator = self.get_file_iterator(filename)
        self.counter = 1
        self.two_b_packer = byte_packer(1)

    def validate_req(self, fname, mode):
        # validate existence
        # validate permissions
        # validate if under process root
        return (fname.decode(encoding='ascii'), mode,)

    def parse_req(self, req):
        print(req)
        rq = req.split(b'\x00')
        print(rq)
        return rq[0], rq[1]

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(next(self.file_iterator))

    def datagram_received(self, data, addr):
        print("receiving dgram {}".format(len(data)))
        print(self.correct_ack(data))
        print(self.is_ack(data))
        if self.is_ack(data) and self.correct_ack(data):
            try:
                print("correct ack")
                self.counter += 1
                print("sending!")
                self.transport.sendto(next(self.file_iterator))
            except StopIteration:
                print("file transfer finished")
                self.transport.close()

    def error_received(self, exc):
        print("Error")
        print(exc)

    def is_ack(self, data):
        return data[:2] == ACK

    def correct_ack(self, data):
        ack_count, = self.two_b_packer.unpack(data[2:4])
        return self.counter == ack_count

    def next_data_pkt(self):
        pkt = b''.join(DAT,
                       self.two_b_packer.pack(self.counter),
                       next(self.file_iterator()))
        return pkt

    def get_file_iterator(self, fname):
        def iterator():
            with open(fname, 'rb') as f:
                while True:
                    contents = f.read(READSIZE)
                    if not contents:
                        break
                    yield contents

        return iterator()

    def connection_lost(self, exc):
        print("conn lost")
        print(exc)


class TftpServer(object):
    def __init__(self, loop):
        self.loop = loop

    def connection_made(self, transport):
        print("conn made")
        self.transport = transport

    def datagram_received(self, data, addr):
        print("received: {}".format(data.decode()))
        # match rrq or wrq or error
        # listen = loop.create_datagram_endpoint(
        # TftpServer,
        # remote_addr=addr)
        # run_until_complete server
        # CHECK if len > x
        tx_type = data[:2]
        chunk = data[2:]
        print(tx_type)
        print(chunk)
        if tx_type == RRQ:
            server = RRQServer
        elif tx_type == WRQ:
            server = WRQServer
        else:
            print("error")
            raise Exception("WUT")
        connect = loop.create_datagram_endpoint(
            lambda: server(chunk, addr),
            remote_addr=addr)

        self.loop.create_task(connect)
        # print("recved!")
        # print(len(data))
        # print(data.decode())
        # self.transport.sendto("nope\n".encode(encoding="ascii"), addr)
        # self.transport.close()

    def connection_lost(self, exc):
        print("conn lost")

loop = asyncio.get_event_loop()

listen = loop.create_datagram_endpoint(
    lambda: TftpServer(loop),
    local_addr=('127.0.0.1', 8069,))

transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_forever()
except KeyboardInterrupt:
    print("Quiting")

transport.close()
loop.close()
