import os
import re

CR = b'\x0d'
LF = b'\x0a'
CRLF = CR + LF
NUL = b'\x00'
CRNUL = CR + NUL
if isinstance(os.linesep, bytes):
    NL = os.linesep
else:
    NL = os.linesep.encode("ascii")


def _multiple_replace(adict):
    rx = re.compile(b'|'.join(map(re.escape, adict)))

    @staticmethod
    def _prototype(data):
        return rx.sub(lambda match: adict[match.group(0)], data)
    return _prototype


class Netascii:
    from_netascii = _multiple_replace({CRLF: NL, CRNUL: CR})
    to_netascii = _multiple_replace({NL: CRLF, CR: CRNUL})

    def __init__(self, reader):
        self._reader = reader
        self._buffer = b''

    def read(self, size):
        buffer_size = 0
        if self._buffer:
            buffer_size = len(self._buffer)
        data = self._buffer + self.to_netascii(
            self._reader.read(size - buffer_size))
        self._buffer = data[size:]
        return data[:size]

    def write(self, data):
        if self._buffer:
            data = self._buffer + data
            self._buffer = b''
        if data[-1:] == CR:
            self._buffer = data[-1:]
            data = data[:-1]
        self._reader.write(self.from_netascii(data))

    def close(self):
        self._reader.close()

    @property
    def closed(self):
        return self._reader.closed

    def flush(self):
        self._reader.flush()
