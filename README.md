# Py3tftp

Py3tftp is an asynchronous [TFTP][1] server written in Python 3.5. It was written for the pure joy of working with Python 3 and implements [RFC 1350][2] (except _mail_ and _netascii_ modes), [RFC 2347][3] (options), [RFC 2348][4] (blksize option), and part of [RFC 2349][5] (timeout, no tsize).

While a toy project, it does adhere to enough of the standards to be useful in real life.

Some Py3k stuff it uses:
- asyncio - [Transports and Protocols][6] for networking.
- asyncio - [Tasks][7] for spinning up extra handlers.
- [New unpacking methods][8] - some sweet stuff right there (3.5+)
- [Tracebacks attached to exceptions][9] - woo!
- Strings are now bytes because all text is unicode

### Usage

Invoking pyt3tftp will start a server that will interact with the current working directory - it will read and write files from it so don't run it in a place with sensitive files!

TFTP has no security features, except for its simplicity:
- It won't overwrite files.
- Nor create non-existant directories.

```
usage: py3tftp [-h] [--host HOST] [-p PORT] [--ack-timeout ACK_TIMEOUT]
               [--conn-timeout CONN_TIMEOUT] [-l FILE_LOG] [-v] [--version]

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           IP of the interface the server will listen on.
                        Default: 0.0.0.0
  -p PORT, --port PORT  Port the server will listen on. Default: 9069. TFTP
                        standard-compliant port: 69 - requires superuser
                        privileges.
  --ack-timeout ACK_TIMEOUT
                        Timeout for each ACK of the lock-step. Default: 0.5.
  --conn-timeout CONN_TIMEOUT
                        Timeout before the server gives up on a transfer and
                        closes the connection. Default: 3.
  -l FILE_LOG, --file-log FILE_LOG
                        Append output to log file.
  -v, --verbose         Enable debug-level logging.
  --version
```

#### Testing

I wrote some simple acceptance tests in `tests/acceptance/*_test.py`. The code is messy as it's meant to be thrown away.

```
python tests/acceptance/*_.py
```

#### Extending the Protocols

There are two protocols: one for handling read requests (RRQProtocol) and one for handling write requests (WRQProtocol). Each has methods that manage the state of a single read or write connection and take care of accepting correct messages, sending replies, reading or writing the next chunk of a file, etc.

Both of these protocol inherit from BaseTFTPProtocol, which takes care of lower level operations such as parsing an initial request, performing OS checks on files (permissions, existance, etc.), as well as tackle resending unacknowledged datagrams and timing out connections. This class mixes in the TFTPOptParserMixin, which parses requests, and validates options and the filename. TFTP options are validated against a dict of supported options in the BaseTFTPProtocol class.

##### Example Scenario

If you'd want to allow py3tftp to handle non-spec protocol options, you'd extend either the RRQProtocol or WRQProtocol class and create a custom `supported_opts` property with the extra option, followed by adding a custom `default_opts` property that contains a default for the new options.

```
class RickAstelyProtocol(RRQProtocol):
    supported_opts = {
        **RRQProtocol.supported_opts, 
        b'nvr_gvup': lambda i: bytes(i, encoding='ascii')}
    default_opts = {
        **RRQProtocol.default_opts,
        b'nvr_gvup': b'let you down'
    }
```

The above ensures that the new option is accepted and made available during a connection.

In order to incorporate the new option, you would look at overloading methods that handle data and connections: `datagram_received`, `connection_made`, `connection_lost`, `initialize_transfer` / `handle_initialization`. In our scenario, we want to check if the requested file contains the _let you down_ string before serving it



#### Roadplan

- fix off-by-one blksize error ie. if you transfer a file 1000 bytes long and set blksize to 1000 bytes, the server won't ack it.
- Add tsize from RFC 2349.
- Add blksize, timeout, and tsize tests.
- Possibly implement RFCs 906 and 951 for fun!

#### LICENSE

The MIT License (MIT)

Copyright (c) 2016 sirMackk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


[1]: https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol
[2]: https://tools.ietf.org/html/rfc1350
[3]: https://tools.ietf.org/html/rfc2347
[4]: https://tools.ietf.org/html/rfc2348
[5]: https://tools.ietf.org/html/rfc2349
[6]: https://docs.python.org/3/library/asyncio-protocol.html
[7]: https://docs.python.org/3/library/asyncio-task.html#task
[8]: https://www.python.org/dev/peps/pep-0448/
[9]: http://legacy.python.org/dev/peps/pep-3109/
