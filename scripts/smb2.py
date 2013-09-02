#!/usr/bin/env/python

def pop_field(Frame, Key):
    if list == type(Frame[Key]):
        return Frame[Key].pop(0)
    else:
        return Frame.pop(Key)

class Cmd:
    SMB2_NEGOTIATE = 0x00
    SMB2_SESSION_SETUP = 0x01
    SMB2_LOGOFF = 0x02
    SMB2_TREE_CONNECT = 0x03
    SMB2_TREE_DISCONNECT = 0x04
    SMB2_CREATE = 0x05
    SMB2_CLOSE = 0x06
    SMB2_FLUSH = 0x07
    SMB2_READ = 0x08
    SMB2_WRITE = 0x09
    SMB2_LOCK = 0x0A
    SMB2_IOCTL = 0x0B
    SMB2_CANCEL = 0x0C
    SMB2_ECHO = 0x0D
    SMB2_QUERY_DIRECTORY = 0x0E
    SMB2_CHANGE_NOTIFY = 0x0F
    SMB2_QUERY_INFO = 0x10
    SMB2_SET_INFO = 0x11
    SMB2_OPLOCK_BREAK = 0x12

    Name = [ 'Negotiate',
             'SessionSetup',
             'Logoff',
             'TreeConnect',
             'TreeDisconnect',
             'Create',
             'Close',
             'Flush',
             'Read',
             'Write',
             'Lock',
             'IoCtl',
             'Cancel',
             'Echo',
             'QueryDirectory',
             'ChangeNotify',
             'QueryInfo',
             'SetInfo',
             'OplockBreak' ]

class Frame:
    def __init__(self, FrameNumber, Timestamp):
        self.frame = FrameNumber
        self.time = Timestamp

class Header(Frame):
    def __init__(self, Command, Sequence, FrameNumber, Timestamp, IsResponse, FrameDict):
        Frame.__init__(self, FrameNumber, Timestamp)
        self.command = Command
        self.sequence = Sequence
        self.response = IsResponse

        self.nt_status = 0
        self.async = False

        if self.response:
            self.nt_status = pop_field(FrameDict, 'smb2.nt_status')

        if 'smb2.flags.async' in FrameDict:
            self.async = FrameDict['smb2.flags.async']

    def is_response(self):
        return self.response

    def is_request(self):
        return not self.response

class Negotiate(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class SessionSetup(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class Logoff(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class TreeConnect(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class TreeDisconnect(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class Create(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.filename = pop_field(Frame, 'smb2.filename')
        elif self.is_response() and self.nt_status == 0:
            self.fid = pop_field(Frame, 'smb2.fid')

class Close(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class Flush(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class Read(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')
            self.offset = pop_field(Frame, 'smb2.file_offset')
            self.read_length = pop_field(Frame, 'smb2.read_length')

class Write(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')
            self.offset = pop_field(Frame, 'smb2.file_offset')
            self.write_length = pop_field(Frame, 'smb2.write_length')

class Lock(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class IoCtl(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class Cancel(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class Echo(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

class QueryDirectory(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class ChangeNotify(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class QueryInfo(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class SetInfo(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

        if self.is_request():
            self.fid = pop_field(Frame, 'smb2.fid')

class OplockBreak(Header):
    def __init__(self, Command, Frame):
        Header.__init__(
            self,
            Command,
            pop_field(Frame, 'smb2.seq_num'),
            Frame['frame.number'],
            Frame['frame.time'],
            pop_field(Frame, 'smb2.flags.response'),
            Frame)

