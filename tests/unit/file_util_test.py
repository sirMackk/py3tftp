import unittest as t
from unittest.mock import MagicMock, patch
from io import BytesIO

from py3tftp.file_io import sanitize_fname, FileReader
from py3tftp.exceptions import FileDoesntExist


class FileReaderTest(t.TestCase):
    def setUp(self):
        self.filename = b'LICENSE'
        self.reader = FileReader(self.filename)

    def test_reads_file(self):
        chunk = self.reader.next_chunk(2048)

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), chunk)

    def test_reads_n_bytes(self):
        bytes_to_read = 12
        chunk = self.reader.next_chunk(bytes_to_read)

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(bytes_to_read), chunk)

    def test_still_has_data_to_read(self):
        bytes_to_read = 4
        data = BytesIO()
        while not self.reader.finished:
            data.write(self.reader.next_chunk(bytes_to_read))

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), data.getvalue())

        self.assertTrue(self.reader.finished)

    def test_raises_doesnt_exist_exc(self):
        with self.assertRaises(FileDoesntExist):
            reader = FileReader(b'DOESNT_EXIST')
            reader.next_chunk()


class TestSanitizeFname(t.TestCase):
    @classmethod
    def setUpClass(cls):
        from os import getcwd
        from os.path import join as path_join
        cls.target_dir = bytes(
            path_join(getcwd(), 'tmp/testfile'),
            encoding='ascii')

    def test_under_root_dir(self):
        fname = b'/tmp/testfile'
        self.assertEqual(sanitize_fname(fname), self.target_dir)

    def test_dir_traversal(self):
        fname = b'../../../../../../tmp/testfile'
        self.assertEqual(sanitize_fname(fname), self.target_dir)
