# CHANGELOG

### 1.2.2 (March 08, 2021)

- Improve filename sanitize to work on Windows (many thanks pkorpine) - https://github.com/sirMackk/py3tftp/pull/15

### 1.2.1 (September 29, 2018)

- Change logger to module logger (thanks schrd!)
- Add flake8 to tests; Fix style issues; Make travis fail on test errors.

### 1.2.0 (September 08, 2018)

- Adds windowsize option handling for RRQ (many thanks jpmzometa!)
- Adds tsize option for RRQ (thanks schrd!)
- handle error packets if client aborts RRQ transfer (thanks schrd!)

### 1.1.0 (August 24, 2018)

- Fixes RRQ not waiting for ACK of last package (thanks jpmzometa!)
- Adds netascii support (thanks keenser!)

### 1.0.2 (March 05, 2018)

- Fixes KeyError bug with the `-l` CLI option (thanks pritstift!)

### 1.0.1 (February 10, 2018)

- Fixes issue #3 - --ack-timeout and --conn-timeout actually work now.

### 1.0.0a (November 26, 2017)

- Fixes issue #1 - implements block number roll over so files over 65535 blocks can be uploaded or downloaded.
- Version bump to 1.0.0a due to fouled up pypi upload.

### 0.0.6 (October 17th, 2016)

- Removes type hints.
- Restructures project into more layers (ie. special packet objects, pulls out file IO from protocols), big API changes.
- Adds a suite of unit tests.
- Adds Travis-CI configuration files.

### 0.0.5 (March 21st, 2016)

- Fixes off by one server response to RRQs that are the multiple of the file's size.
- Adds type hints.
- Makes 'long description' rst.
- Adds test.sh to make running tests easier.

### 0.0.4 (March x, 2016)

- Adds CHANGELOG.md
- Fixes blksize errors.
- Adds tests for blksize and timeout options.
- Improves tftp option handling.


### 0.0.3 (March 1st, 2016)

- Restructuring for easier reuse.
- Fixed leftover file descriptor issue.

###0.0.2 (February 25th, 2016)

- Adds rfc2347 support.
- Adds rfc2348 (blksize) support.
- Adds part of rfc2349 support (timeout, no tsize).
- Adds final setup.py stuff.
