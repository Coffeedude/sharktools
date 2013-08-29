#!/usr/bin/env python

import sys
import pyshark
import smb2


frame_fields = ['frame.number',
                'frame.time']

smb2_fields = ['smb2.flags.response',
               'smb2.cmd',
               'smb2.response_in',
               'smb2.response_to',
               'smb2.filename',
               'smb2.fid',
               'smb2.tag' ]

fields = frame_fields + smb2_fields

if len(sys.argv) < 2:
    print >> sys.stderr, "usage: %s <pcap filename>" % (sys.argv[0])
    sys.exit(1)

pcap_file = pyshark.read(
            sys.argv[1],
            fields,
            'smb2')

for frame in pcap_file:
    smb2_op = smb2.Smb2Frame(
                  frame['frame.number'],
                  frame['frame.time'],
                  frame)
    if smb2_op.isRequest():
        print >> sys.stdout, "{0:>5} => {1}".format(
            smb2_op.frame_number,
            smb2.Command.Name[smb2_op.packet['smb2.cmd']])
