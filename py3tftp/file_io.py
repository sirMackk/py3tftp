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
        self._f = None
        self.finished = False

    def _get_file(self):
        try:
            with open(self.fname, 'rb') as f:
                while True:
                    yield f
        except FileNotFoundError:
            raise FileDoesntExist('Cannot open {0}'.format(self.fname))

    def next_chunk(self, size=0):
        if not self._f:
            self._f = self._get_file()
        data = next(self._f).read(size)

        if not data:
            self.finished = True

        return data
