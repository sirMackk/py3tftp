import os
import os.path as opath


def sanitize_fname(fname):
    """
    Ensures that fname is a path under the current working directory.
    """
    root_dir = os.getcwd()
    return opath.join(
        bytes(root_dir, encoding='ascii'),
        opath.normpath(
            b'/' + fname).lstrip(b'/'))


class FileReader(object):
    """
    A wrapper around a regular file that implements:
    - read_chunk - for closing the file when bytes read is
      less than chunk_size.
    - finished - for easier notifications
    interfaces.
    When it goes out of scope, it ensures the file is closed.
    """

    def __init__(self, fname, chunk_size=0):
        self.fname = sanitize_fname(fname)
        self.chunk_size = chunk_size
        self._f = None
        self._f = self._open_file()
        self.finished = False

    def _open_file(self):
        return open(self.fname, 'rb')

    def read_chunk(self, size=None):
        size = size or self.chunk_size
        if self.finished:
            return b''

        data = self._f.read(size)

        if not data or (size > 0 and len(data) < size):
            self._f.close()
            self.finished = True

        return data

    def __del__(self):
        if self._f and not self._f.closed:
            self._f.close()


class FileWriter(object):
    """
    Wrapper around a regular file that implements:
    - write_chunk - for closing the file when bytes written
      is less than chunk_size.
    When it goes out of scope, it ensures the file is closed.
    """
    def __init__(self, fname, chunk_size):
        self.fname = fname
        self.chunk_size = chunk_size
        self._f = None
        self._f = self._open_file()

    def _open_file(self):
        return open(self.fname, 'xb')

    def _flush(self):
        if self._f:
            self._f.flush()

    def write_chunk(self, data):
        bytes_written = self._f.write(data)

        if not data or len(data) < self.chunk_size:
            self._f.close()

        return bytes_written

    def __del__(self):
        if self._f and not self._f.closed:
            self._f.close()
