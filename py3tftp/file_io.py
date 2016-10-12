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
        self.finished = False

    def _get_file_gen(self):
        try:
            with open(self.fname, 'rb') as f:
                while True:
                    yield f
        except FileNotFoundError:
            raise FileDoesntExist('Cannot open {0}'.format(self.fname))

    def read_chunk(self, size=0):
        if not self._f_gen:
            self._f_gen = self._get_file_gen()
        data = next(self._f_gen).read(size)

        if not data:
            self.finished = True

        return data


class FileWriter(object):
    def __init__(self, fname, chunk_size):
        self.fname = fname
        self.chunk_size = chunk_size
        self._f_gen = None
        self._f = None

    def _get_file_gen(self):
        with open(self.fname, 'xb') as f:
            self._f = f
            while True:
                data = yield
                f.write(data)
                if len(data) < self.chunk_size:
                    self._f = None
                    break
        yield None

    def _flush(self):
        if self._f_gen:
            self._f_gen.send(b'')

    def write_chunk(self, data):
        if not self._f_gen:
            self._f_gen = self._get_file_gen()
            self._f_gen.send(None)
        self._f_gen.send(data)
        return len(data)
