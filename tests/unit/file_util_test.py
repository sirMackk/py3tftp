import unittest as t
from unittest.mock import MagicMock, patch
from io import BytesIO
import os

from py3tftp.file_io import sanitize_fname, FileReader, FileWriter
from py3tftp.exceptions import FileDoesntExist


class FileReaderTest(t.TestCase):
    def setUp(self):
        self.filename = b'LICENSE'
        self.reader = FileReader(self.filename)

    def test_reads_file(self):
        chunk = self.reader.read_chunk(2048)

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), chunk)

    def test_reads_n_bytes(self):
        bytes_to_read = 12
        chunk = self.reader.read_chunk(bytes_to_read)

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(bytes_to_read), chunk)

    def test_still_has_data_to_read(self):
        bytes_to_read = 4
        data = BytesIO()
        while not self.reader.finished:
            data.write(self.reader.read_chunk(bytes_to_read))

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), data.getvalue())

        self.assertTrue(self.reader.finished)

    def test_raises_doesnt_exist_exc(self):
        with self.assertRaises(FileNotFoundError):
            reader = FileReader(b'DOESNT_EXIST')
            reader.read_chunk()

    def test_fd_closed_after_reading(self):
        fd = self.reader._f.fileno()
        self.reader.read_chunk(2048)

        with self.assertRaises(OSError):
            print(os.fstat(fd))


class FileWriterTest(t.TestCase):
    def setUp(self):
        self.filename = b'TEST_FILE'
        self.msg = b'test msg'
        self.chk_size = len(self.msg)
        self.writer = FileWriter(self.filename, self.chk_size)

    def tearDown(self):
        if os.path.exists(self.filename):
            os.unlink(self.filename)

    def test_writes_full_file_to_disk(self):
        self.writer.write_chunk(self.msg)

        self.assertTrue(os.path.exists(self.filename))

        self.writer._flush()
        with open(self.filename, 'rb') as f:
            self.assertEqual(self.msg, f.read())

    def test_write_chunk_returns_no_bytes_written(self):
        bytes_written = self.writer.write_chunk(self.msg)
        self.assertEqual(len(self.msg), bytes_written)

    def test_doesnt_overwrite_file_raises_exc(self):
        self.writer.write_chunk(self.msg)
        with self.assertRaises(FileExistsError):
            writer2 = FileWriter(self.filename, len(self.msg))
            writer2.write_chunk(self.msg)

    def test_fd_closed_after_everything_written_out(self):
        self.writer.write_chunk(self.msg)

        fd = self.writer._f.fileno()
        self.writer._flush()

        # simulate the writer obj going out of scope
        del self.writer

        with self.assertRaises(OSError):
            os.fstat(fd)


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
