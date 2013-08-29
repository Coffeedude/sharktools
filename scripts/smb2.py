#!/usr/bin/env/python

class Command:
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

SMB2_FLAGS_RESPONSE = 'smb2.flags.response'

class Frame:
    def __init__(self, FrameNumber, Timestamp):
        self.frame_number = FrameNumber
        self.time_stamp = Timestamp

class Smb2Frame(Frame):
    def __init__(self, FrameNumber, Timestamp, fields):
        Frame.__init__(self, FrameNumber, Timestamp)
        self.packet = fields

    def isRequest(self):
        if SMB2_FLAGS_RESPONSE in self.packet:
            return self.packet[SMB2_FLAGS_RESPONSE] == False
        else:
            return False

