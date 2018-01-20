import logging
import asyncio

from .protocols import TFTPServerProtocol
from .cli_parser import parse_cli_arguments


def main():
    args = parse_cli_arguments()

    logging.info('Starting TFTP server on {addr}:{port}'.format(
        addr=args.host, port=args.port))

    timeouts = {
        bytes(k, encoding='ascii'): v
        for k, v in vars(args).items() if 'timeout' in k
    }
    loop = asyncio.get_event_loop()

    listen = loop.create_datagram_endpoint(
        lambda: TFTPServerProtocol(args.host, loop, timeouts),
        local_addr=(args.host, args.port,))

    transport, protocol = loop.run_until_complete(listen)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info('Received signal, shutting down')

    transport.close()
    loop.close()


if __name__ == '__main__':
    main()
