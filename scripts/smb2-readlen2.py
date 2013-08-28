#!/usr/bin/env python

import sys
import pyshark


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print >> sys.stderr, "usage: %s <pcap filename>" % (sys.argv[0])
        sys.exit(1)

    print "Opening file: %s" % (sys.argv[1])

    f = pyshark.read(
            sys.argv[1],
            ['smb2.read_length',
             'smb2.write_length',
             'smb2.file_offet', ],
            'smb2 && smb2.cmd == 8 && smb2.flags.response == 1')

    b = list(f)
    lengths = {}
    for i in range(len(b)):
        if list == type(b[i]['smb2.read_length']):
            for j in range(len(b[i]['smb2.read_length'])):
                if str(b[i]['smb2.read_length'][j]) in lengths:
                    lengths[str(b[i]['smb2.read_length'][j])] += 1
                else:
                    lengths[str(b[i]['smb2.read_length'][j])] = 1
        else:
            if str(b[i]['smb2.read_length']) in lengths:
                lengths[str(b[i]['smb2.read_length'])] += 1
            else:
                lengths[str(b[i]['smb2.read_length'])] = 1

    key_list = [int(x) for x in lengths.keys()]
    for k in sorted(key_list):
       print "%s, %s" % (k, lengths[str(k)])

