class Py3tftpError(Exception):
    pass


class ProtocolException(Py3tftpError):
    pass


class UnacknowledgedOption(Py3tftpError):
    pass


class BadRequest(Py3tftpError):
    pass


class BadPacketType(Py3tftpError):
    pass
