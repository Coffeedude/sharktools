#!/usr/bin/env python

import sys
import pyshark

class Smb2Frame:


smb2_cmds = [ 'Negotiate',
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

if len(sys.argv) < 2:
    print >> sys.stderr, "usage: %s <pcap filename>" % (sys.argv[0])
    sys.exit(1)

print "Opening file: %s" % (sys.argv[1])

fpcap = pyshark.read(
            sys.argv[1],
            ['frame.number',
             'smb2.flags.response',
             'smb2.response_in',
             'smb2.response_to',
             'smb2.filename',
             'smb2.fid',
             'smb2.tag' ],
            'smb2 && smb2.cmd == 5')

frames = list(fpcap)
com_create_dict = {}
lifetime = {}

for i in range(len(frames)):
    if frames[i]['smb2.flags.response'] == False:
        if
        print >> sys.stdout, frames[i]
        #print >> sys.stdout, "{0:>5} request".format(frames[i]['frame.number'])
