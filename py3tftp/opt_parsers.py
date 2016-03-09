import os
import os.path as opath
import logging

from .exceptions import UnacknowledgedOption


class TFTPOptParserMixin(object):
    def validate_req(self, fname, mode, opts):
        """
        Filters 'opts' to get rid of options absent from self.supported_opts
        and casts the filtered options to expected types.
        """
        options = {}
        for option, value in opts.items():
            logging.debug(option)
            if option in self.supported_opts.keys():
                logging.debug(option)
                try:
                    options[option] = self.supported_opts[option]()(value)
                except UnacknowledgedOption as e:
                    logging.debug(e)
                except ValueError:
                    logging.debug(
                        ('Client passed malformed option "{0}": "{1}", '
                         'ignoring').format(option, value))

        return (fname.decode(encoding='ascii'), mode, options)

    def parse_req(self, req):
        """
        Seperates \x00 delimited byte string contents according to RFC1350:
        'filename\x00mode\x00opt1\x00val1\x00optN\x00valN\x00' into a
        filename, a mode, and a dictionary of option:values.
        """
        logging.debug("Reqest: {}".format(req))
        fname, mode, *opts = [item for item in req.split(b'\x00') if item]
        options = dict(zip(opts[::2], opts[1::2]))
        return fname, mode, options

    def sanitize_fname(self, fname):
        """
        Ensures that fname is a path under the current working directory.
        """
        root_dir = os.getcwd()
        return opath.join(
            root_dir,
            opath.normpath(
                '/' + fname).lstrip('/'))


class BlksizeParser(object):
    lower_bound = 8
    upper_bound = 65464

    def __call__(self, value):
        return self._validate(int(value))

    def _validate(self, value):
        if value > self.upper_bound:
            return value - (value - self.upper_bound)
        elif value < self.lower_bound:
            raise UnacknowledgedOption(
                'Requested blksize "{0}" below RFC-spec limit ({1})'.format(
                    value, self.lower_bound))
        else:
            return value


class TimeoutParser(object):
    lower_bound = 1
    upper_bound = 255

    def __call__(self, value):
        return self._validate(float(value))

    def _validate(self, value):
        if value > self.upper_bound or value < self.lower_bound:
            raise UnacknowledgedOption(
                ('Requested timeout "{0}" outside of RFC-spec range '
                 '({1} - {2})').format(
                     value, self.lower_bound, self.upper_bound))
        else:
            return value
