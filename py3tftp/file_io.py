import os
import os.path as opath

from py3tftp.exceptions import FileDoesntExist


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
    def __init__(self, fname):
        self.fname = sanitize_fname(fname)
        self._f_gen = None
        self._f = None
        self.finished = False

    def _get_file(self):
        try:
            self._f = open(self.fname, 'rb')
            return self._f
        except FileNotFoundError:
            raise FileDoesntExist('Cannot open {0}'.format(self.fname))

    def read_chunk(self, size=0):
        if self.finished:
            return b''

        if not self._f:
            self._get_file()
        data = self._f.read(size)

        if not data or (size > 0 and len(data) < size):
            self._f.close()
            self.finished = True

        return data

    def __del__(self):
        if self._f and not self._f.closed:
            self._f.close()


class FileWriter(object):
    def __init__(self, fname, chunk_size):
        self.fname = fname
        self.chunk_size = chunk_size
        self._f = None

    def _get_file(self):
        self._f = open(self.fname, 'xb')

        # with open(self.fname, 'xb') as f:
            # self._f = f
            # while True:
                # data = yield
                # f.write(data)
                # if len(data) < self.chunk_size:
                    # self._f = None
                    # break
        # yield None

    def _flush(self):
        if self._f:
            self._f.flush()

    def write_chunk(self, data):
        if not self._f:
            self._get_file()

        bytes_written = self._f.write(data)

        if not data or len(data) < self.chunk_size:
            self._f.close()

        return bytes_written

    def __del__(self):
        if self._f and not self._f.closed:
            self._f.close()
