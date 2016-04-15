class TFTPPacketFactory(object):
    @classmethod
    def create_packet(cls, type=None, **kwargs):
        if type in ('RRQ', 'WRQ'):
            return TFTPRequestPacket(type, **kwargs)
        elif type == 'DAT':
            return TFTPDatPacket(**kwargs)
        elif type == 'ACK':
            return TFTPAckPacket(**kwargs)
        elif type == 'OCK':
            return TFTPOckPacket(**kwargs)
        elif type == 'ERR':
            return TFTPErrPacket(**kwargs)

    @classmethod
    def from_bytes(cls, data):
        try:
            type = self.pkt_types[data[:2]].decode('ascii').upper()
        except KeyError:
            pass  # bad packet type, discard

        if type in ('RRQ', 'WRQ'):
            fname, mode, r_opts = tftp_parsing.validate_req(
                *tftp_parsing.parse_req(data))
            return cls.create_packet(
                type=type,
                fname=fname,
                mode=mode,
                r_opts=r_opts)
        elif type == 'DAT':
            block_no = BaseTFTPPacket.unpack_short(data[2:4])
            return cls.create_packet(
                type=type,
                block_no=block_no,
                data=data[4:])
        elif type == 'ACK':
            block_no = BaseTFTPPacket.unpack_short(data[2:4])
            return cls.create_packet(
                type=type,
                block_no=block_no)
        elif type == 'OCK':
            return cls.create_packet(type=type, opts=r_opts)
        elif type == 'ERR':
            code = BaseTFTPPacket.unpack_short(data[2:4])
            msg = data[4:]
            return cls.create_packet(type, code=code, msg=msg)

    @classmethod
    def err_file_exists(cls) -> bytes:
        return cls.create_packet('err', 6, 'File already exists')

    @classmethod
    def err_access_violation(self) -> bytes:
        return cls.create_packet('err', 2, 'Access violation')

    @classmethod
    def err_file_not_found(self) -> bytes:
        return cls.create_packet('err', 1, 'File not found')

    @classmethod
    def err_unknown_tid(self) -> bytes:
        return cls.create_packet('err', 5, 'Unknown transfer id')


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
        self.type = None
        self._bytes_cache = None

    def to_bytes(self):
        raise NotImplementedError

    def is_ack(self, data: bytes) -> bool:
        return self.type == 'ACK'

    def is_correct_sequence(self, expected_block_no: int) -> bool:
        """
        Checks whether incoming data packet has the expected block number.
        """
        return expected_block_no == self.block_no

    def is_data(self) -> bool:
        return self.type == 'DAT'

    def is_err(self, pkt: bytes) -> bool:
        return self.type == 'ERR'

    def serialize_options(self, optns):
        opt_items = [val for pair in self.options.items() for val in pair]
        opt_items = [str(val).encode('ascii') for val in opt_items]
        return b'\x00'.join(opt_items)

    @property
    def size(self):
        return len(self.to_bytes())

    @classmethod
    def number_to_bytes(val: Union[int, float]) -> bytes:
        """
        Changes a number to an ascii byte string.
        """
        return bytes(str(int(val)), encoding='ascii')

    @classmethod
    def pack_short(number: int) -> bytes:
        """
        Create big-endian short byte string out of integer.
        """
        return number.to_bytes(2, byteorder='big')

    @classmethod
    def unpack_short(data: bytes) -> int:
        """
        Create integer out of big-endian short byte string.
        """
        return int.from_bytes(data, byteorder='big')


class TFTPRequestPacket(BaseTFTPPacket):
    def __init__(self, type, **kwargs):
        self.type = type.upper().encode('ascii')
        self.fname = kwargs['fname'].encode('ascii')
        self.mode = kwargs['mode'].encode('ascii')
        self.r_opts = kwargs.get('r_opts', {})

    def to_bytes(self):
        return b''.join([self.pkt_types[self.type],
                         self.fname.decode('ascii'),
                         self.mode.decode('ascii'),
                         self.serialize_options(self.r_opts),
                         b'\x00'])


class TFTPAckPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__(self)
        self.type = 'ACK'
        self.block_no = kwargs['block_no']

    def to_bytes(self):
        return b''.join([self.pkt_types['ACK'],
                         BaseTFTPPacket.pack_short(self.block_no)])


class TFTPDatPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__(self)
        self.type = 'DAT'

        self.block_no = kwargs['block_no']
        self.data = kwargs['data']

    def to_bytes(self):
        return b''.join([self.pkt_types['DAT'],
                         BaseTFTPPacket.pack_short(self.block_no),
                         self.data])


class TFTPOckPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__(self)
        self.type = 'OCK'
        self.options = kwargs.get('r_opts', {})

    def to_byte(self):
        return b''.join([self.pkt_types['OCK'],
                         self.serialize_options(self.options)])


class TFTPErrPacket(BaseTFTPPacket):
    def __init__(self, **kwargs):
        super().__init__(self)
        self.type = 'ERR'
        self.code = kwargs['code']
        self.msg = kwargs['msg']

    def to_bytes(self):
        return b''.join([self.pkt_types['OCK'],
                         BaseTFTPPacket.pack_short(self.code),
                         self.msg.encode('ascii'),
                         b'\x00'])
