class Py3tftpError(Exception):
    pass


class ProtocolException(Py3tftpError):
    pass


class UnacknowledgedOption(Py3tftpError):
    pass
