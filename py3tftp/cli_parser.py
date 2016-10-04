import argparse
import logging
from sys import exit

from py3tftp import __version__

EPILOG = """
Released under the MIT license.
Copyright 2016 Matt O. <matt@mattscodecave.com>
"""

logging_config = {
    'format': '%(asctime)s [%(levelname)s] %(message)s',
    'level': logging.INFO,
    'filename': None
}


def print_version():
    print("py3tftp version: {}".format(__version__))


def parse_cli_arguments():
    parser = argparse.ArgumentParser(epilog=EPILOG)
    parser.add_argument('--host',
                        default='0.0.0.0',
                        help=('IP of the interface the server will listen on. '
                              'Default: 0.0.0.0'))
    parser.add_argument(
        '-p',
        '--port',
        default=9069,
        type=int,
        help=('Port the server will listen on. '
              'Default: 9069. TFTP standard-compliant port: 69 - '
              'requires superuser privileges.'))
    parser.add_argument(
        '--ack-timeout',
        default=0.5,
        type=float,
        help='Timeout for each ACK of the lock-step. Default: 0.5.')
    parser.add_argument(
        '--conn-timeout',
        dest="timeout",
        default=3.0,
        type=float,
        help=('Timeout before the server gives up on a transfer and closes '
              'the connection. Default: 3.'))
    parser.add_argument('-l', '--file-log', help='Append output to log file.')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Enable debug-level logging.')
    parser.add_argument('--version', action='store_true')

    args = parser.parse_args()

    if args.verbose:
        logging_config['level'] = logging.DEBUG

    if args.file_log:
        logging_config['filename'] = args.log

    if args.version:
        print_version()
        exit()

    logging.basicConfig(**logging_config)
    return args
