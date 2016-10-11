import unittest as t

from py3tftp.exceptions import UnacknowledgedOption, BadRequest
from py3tftp.tftp_parsing import (
    validate_req, parse_req, blksize_parser,
    timeout_parser)


class TestTimeoutParser(t.TestCase):
    def test_lower_bound(self):
        low_val = b'-11'
        with self.assertRaises(UnacknowledgedOption):
            timeout_parser(low_val)

    def test_upper_bound(self):
        high_val = b'999'
        with self.assertRaises(UnacknowledgedOption):
            timeout_parser(high_val)

    def test_float_within_acceptable_range(self):
        val = b'20.5'
        self.assertEqual(timeout_parser(val), 20.5)

    def test_garbage_data(self):
        val = b'\x41'
        with self.assertRaises(ValueError):
            timeout_parser(val)


class TestBlksizeParser(t.TestCase):
    def test_lower_bound(self):
        low_val = b'4'
        with self.assertRaises(UnacknowledgedOption):
            blksize_parser(low_val)

    def test_upper_bound_capped(self):
        high_val = b'70000'
        self.assertEqual(blksize_parser(high_val, upper_bound=4096), 4096)

    def test_int_within_acceptable_range(self):
        val = b'2048'
        self.assertEqual(blksize_parser(val), 2048)

    def test_garbage_data(self):
        val = b'\x41'
        with self.assertRaises(ValueError):
            blksize_parser(val)


class TestParseReq(t.TestCase):
    def test_not_enough_values(self):
        req = b'fname\x00'
        with self.assertRaises(BadRequest):
            parse_req(req)

    def test_odd_number_of_opts(self):
        req = b'fname\x00mode\x00opt1\x00val1\x00opt2'
        fname, mode, opts = parse_req(req)
        self.assertDictEqual(opts, {b'opt1': b'val1'})

    def test_correct_output(self):
        req = b'fname\x00mode\x00opt1\x00val1\x00opt2\x00val2'
        fname, mode, opts = parse_req(req)
        self.assertEqual(fname, b'fname')
        self.assertEqual(mode, b'mode')
        self.assertDictEqual(opts, {b'opt1': b'val1', b'opt2': b'val2'})


class TestValidateReq(t.TestCase):
    def setUp(self):
        self.fname = b'fname'
        self.mode = b'mode'
        self.opts = {b'opt1': b'val1'}
        self.opt1_parser = lambda opt: opt.decode('ascii')

    def test_fname_is_ascii(self):
        fname, *_ = validate_req(self.fname, self.mode, self.opts)
        self.assertEqual(fname, 'fname')

    def test_drops_unsupported_opts(self):
        _, _, opts = validate_req(
            self.fname,
            self.mode,
            self.opts,
            supported_opts={b'opt1': self.opt1_parser})
        self.assertDictEqual(opts, {b'opt1': 'val1'})

    def test_drops_garbage_opts(self):
        _, _, opts = validate_req(
            self.fname,
            self.mode,
            {**self.opts, **{b'opt2': 'val2'}},
            supported_opts={b'opt1': self.opt1_parser})
        self.assertDictEqual(opts, {b'opt1': 'val1'})
