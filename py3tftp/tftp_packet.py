from typing import Union

from py3tftp import tftp_parsing
from py3tftp.exceptions import BadRequest


class TFTPPacketFactory(object):
    def __init__(self, supported_opts=None, default_opts=None):
        if not supported_opts:
            supported_opts = {}

        if not default_opts:
            default_opts = {}

        self.supported_opts = supported_opts
        self.default_opts = default_opts


    @classmethod
    def create_packet(cls, pkt_type=None, **kwargs):
        if pkt_type in ('RRQ', 'WRQ'):
            return TFTPRequestPacket(pkt_type, **kwargs)
        elif pkt_type == 'DAT':
            return TFTPDatPacket(**kwargs)
        elif pkt_type == 'ACK':
            return TFTPAckPacket(**kwargs)
        elif pkt_type == 'OCK':
            return TFTPOckPacket(**kwargs)
        elif pkt_type == 'ERR':
            return TFTPErrPacket(**kwargs)

    def from_bytes(self, data):
        try:
            pkt_type = BaseTFTPPacket.pkt_types[data[:2]].upper()
        except KeyError:
            raise BadRequest()

        if pkt_type in ('RRQ', 'WRQ'):
            fname, mode, r_opts = tftp_parsing.validate_req(
                *tftp_parsing.parse_req(data),
                supported_opts=self.supported_opts,
                default_opts=self.default_opts)
            return self.create_packet(
                pkt_type=pkt_type,
                fname=fname,
                mode=mode,
                r_opts=r_opts)
        elif pkt_type == 'DAT':
            block_no = BaseTFTPPacket.unpack_short(data[2:4])
            return self.create_packet(
                pkt_type=pkt_type,
                block_no=block_no,
                data=data[4:])
        elif pkt_type == 'ACK':
            block_no = BaseTFTPPacket.unpack_short(data[2:4])
            return self.create_packet(
                pkt_type=pkt_type,
                block_no=block_no)
        elif pkt_type == 'OCK':
            _, _, r_opts = tftp_parsing.validate_req(
                *tftp_parsing.parse_req(data),
                supported_opts=self.supported_opts,
                default_opts=self.default_opts)
            return self.create_packet(pkt_type=pkt_type, opts=r_opts)
        elif pkt_type == 'ERR':
            code = BaseTFTPPacket.unpack_short(data[2:4])
            msg = data[4:]
            return self.create_packet(pkt_type, code=code, msg=msg)

    @classmethod
    def err_file_exists(cls) -> bytes:
        return cls.create_packet('ERR', code=6, msg='File already exists')

    @classmethod
    def err_access_violation(cls) -> bytes:
        return cls.create_packet('ERR', code=2, msg='Access violation')

    @classmethod
    def err_file_not_found(cls) -> bytes:
        return cls.create_packet('ERR', code=1, msg='File not found')

    @classmethod
    def err_unknown_tid(cls) -> bytes:
        return cls.create_packet('ERR', code=5, msg='Unknown transfer id')


class BaseTFTPPacket(object):
    pkt_types = {
        b'\x00\x01': 'RRQ',
        b'\x00\x02': 'WRQ',
        b'\x00\x03': 'DAT',
        b'\x00\x04': 'ACK',
        b'\x00\x05': 'ERR',
        b'\x00\x06': 'OCK',
        'RRQ': b'\x00\x01',
        'WRQ': b'\x00\x02',
        'DAT': b'\x00\x03',
        'ACK': b'\x00\x04',
        'ERR': b'\x00\x05',
        'OCK': b'\x00\x06',
    }

    def __init__(self):
        self.pkt_type = None
        self._bytes_cache = None

    def to_bytes(self):
        raise NotImplementedError

    def is_ack(self) -> bool:
        return self.pkt_type == 'ACK'

    def is_correct_sequence(self, expected_block_no: int) -> bool:
        """
        Checks whether incoming data packet has the expected block number.
        """
        return expected_block_no == self.block_no

    def is_data(self) -> bool:
        return self.pkt_type == 'DAT'

    def is_err(self)-> bool:
        return self.pkt_type == 'ERR'

    def is_rrq(self) -> bool:
        return self.pkt_type == 'RRQ'

    def is_wrq(self) -> bool:
        return self.pkt_type == 'WRQ'

    def is_ock(self) -> bool:
        return self.pkt_type == 'OCK'

    @property
    def size(self):
        return len(self.to_bytes())

    @classmethod
    def serialize_options(cls, options):
        opt_items = [val for pair in options.items() for val in pair]
        opt_items = [str(val).encode('ascii') for val in opt_items]
        return b'\x00'.join(opt_items)

    @classmethod
    def number_to_bytes(cls, val: Union[int, float]) -> bytes:
        """
        Changes a number to an ascii byte string.
        """
        return bytes(str(int(val)), encoding='ascii')

    @classmethod
    def pack_short(cls, number: int) -> bytes:
        """
        Create big-endian short byte string out of integer.
        """
        return number.to_bytes(2, byteorder='big')

    @classmethod
    def unpack_short(cls, data: bytes) -> int:
        """
        Create integer out of big-endian short byte string.
        """
        return int.from_bytes(data, byteorder='big')


def text_to_bytes(string):
    if not isinstance(string, bytes):
        return bytes(string, encoding='ascii')
    return string


class TFTPRequestPacket(BaseTFTPPacket):
    def __init__(self, pkt_type, **kwargs):
        super().__init__()
        self.pkt_type = pkt_type.upper()
        self.fname = text_to_bytes(kwargs['fname'])
        self.mode = text_to_bytes(kwargs['mode'])
        self.r_opts = kwargs.get('r_opts', {})

    def to_bytes(self):
        packet = [self.pkt_types[self.pkt_type] + self.fname,
                  self.mode,
                  BaseTFTPPacket.serialize_options(self.r_opts)]

        return b'\x00'.join([part for part in packet if part]) + b'\x00'


class TFTPAckPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__()
        self.pkt_type = 'ACK'
        self.block_no = kwargs['block_no']

    def to_bytes(self):
        return b''.join([self.pkt_types['ACK'],
                         BaseTFTPPacket.pack_short(self.block_no)])


class TFTPDatPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__()
        self.pkt_type = 'DAT'

        self.block_no = kwargs['block_no']
        self.data = kwargs['data']

    def to_bytes(self):
        return b''.join([self.pkt_types['DAT'],
                         BaseTFTPPacket.pack_short(self.block_no),
                         self.data])


class TFTPOckPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__()
        self.pkt_type = 'OCK'
        self.options = kwargs.get('r_opts', {})

    def to_bytes(self):
        return b''.join([self.pkt_types['OCK'],
                         BaseTFTPPacket.serialize_options(self.options),
                         b'\x00'])


class TFTPErrPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__()
        self.pkt_type = 'ERR'
        self.code = kwargs['code']
        self.msg = kwargs['msg']

    def to_bytes(self):
        return b''.join([self.pkt_types['ERR'],
                         BaseTFTPPacket.pack_short(self.code),
                         self.msg.encode('ascii'),
                         b'\x00'])
