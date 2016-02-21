import argparse
import logging
from sys import exit


def print_version():
    pass
    print("Version: {}".format('0.0.1'))


def print_help():
    print("Help")


def parse_cli_arguments():
    logging_config = {
        'format': '%(asctime)s [%(levelname)s] %(message)s',
        'level': logging.INFO,
        'filename': None
    }

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('-p', '--port', default=9069)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-l', '--log')
    parser.add_argument('--version', action='store_true')
    parser.add_argument('-h', '--help', action='store_true')

    args = parser.parse_args()

    if args.verbose:
        logging_config['level'] = logging.DEBUG

    if args.log:
        # also make output to stdout + toggle
        logging_config['filename'] = args.log

    if args.version:
        print_version()
        exit()

    if args.help:
        print_help()
        exit()

    logging.basicConfig(**logging_config)
    return args
