import os
import os.path as opath
import typing
from typing import Tuple, Dict, Any
import logging

from .exceptions import UnacknowledgedOption


class TFTPOptParserMixin(object):
    """
    This mixin adds methods that parse TFTP read/write requests, TFTP options,
    as well as parse filenames.
    """

    def validate_req(self,
                     fname: bytes,
                     mode: bytes,
                     opts: Dict[bytes, Any]) -> Tuple[bytes,
                                                      bytes,
                                                      Dict[bytes, Any]]:
        """
        Reads a RRQ or WRQ and parses it for a filename, a mode, and
        optionally, a list of TFTP options.
        """
        options = {} # type: Dict[bytes, Any]
        for option, value in opts.items():
            logging.debug(option)
            if option in self.supported_opts.keys():
                logging.debug(option)
                try:
                    options[option] = self.supported_opts[option](value)
                except UnacknowledgedOption as e:
                    logging.debug(e)
                except ValueError:
                    logging.debug(
                        ('Client passed malformed option "{0}": "{1}", '
                         'ignoring').format(option, value))

        return (fname.decode(encoding='ascii'), mode, options)

    def parse_req(self,
                  req: bytes) -> Tuple[bytes,
                                       bytes,
                                       Dict[bytes, Any]]:
        """
        Seperates \x00 delimited byte string contents according to RFC1350:
        'filename\x00mode\x00opt1\x00val1\x00optN\x00valN\x00' into a
        filename, a mode, and a dictionary of option:values.
        """
        logging.debug("Reqest: {}".format(req))
        fname, mode, *opts = [item for item in req.split(b'\x00') if item]
        options = dict(zip(opts[::2], opts[1::2]))
        return fname, mode, options

    def sanitize_fname(self, fname: bytes) -> bytes:
        """
        Ensures that fname is a path under the current working directory.
        """
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))


def blksize_parser(val: bytes) -> int:
    """
    Parses and validates the 'blksize' option against the RFC 2348.
    """
    lower_bound = 8
    upper_bound = 65464

    value = int(val)
    if value > upper_bound:
        return value - (value - upper_bound)
    elif value < lower_bound:
        raise UnacknowledgedOption(
            'Requested blksize "{0}" below RFC-spec limit ({1})'.format(
                value, lower_bound))
    else:
        return value


def timeout_parser(val: bytes) -> float:
    """
    Parses and validates the 'timeout' option against RFC 2349.
    """
    lower_bound = 1
    upper_bound = 255

    value = float(val)

    if value > upper_bound or value < lower_bound:
        raise UnacknowledgedOption(
            ('Requested timeout "{0}" outside of RFC-spec range '
             '({1} - {2})').format(value, lower_bound, upper_bound))
    else:
        return value
