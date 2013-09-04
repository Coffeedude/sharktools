#!/usr/bin/env python

import sys
import pyshark
import smb2

fields = [
    'frame.number',
    'frame.time',
    'smb2.cmd',
    'smb2.credit.charge',
    'smb2.seq_num',
    'smb2.aid',
    'smb2.tid',
    'smb2.sesid',
    'smb2.nt_status',
    'smb2.flags.response',
    'smb2.flags.async',
    'smb2.filename',
    'smb2.read_length',
    'smb2.write_length',
    'smb2.file_offset',
    'smb2.fid'
    ]

'''
def get_file_id(OpList):
    command = OpList[0].command

    if command == smb2.SMB2_CREATE:
        pass
    elif command == :
        pass
'''
def op_complete(OpList):
    has_request = False
    has_response = False

    for i in range(len(OpList)):
        if OpList[i].is_response():
            has_response = True
        else:
            has_request = True

    return (has_request and has_response)

if len(sys.argv) < 2:
    sys.argv.append('/home/coffeedude/Desktop/sample_smb.pcap')
    #print >> sys.stderr, "usage: %s <pcap filename>" % (sys.argv[0])
    #sys.exit(1)

pcap_file = pyshark.read(
            sys.argv[1],
            fields,
            'smb2')

smb2_ops = {}

for frame in pcap_file:
    commands = frame.pop('smb2.cmd')
    if list != type(commands):
        commands = [commands]

    for i in range(len(commands)):

        try:
            op = smb2.factory[commands[i]](commands[i], frame)
        except KeyError, e:
            print smb2.Cmd.Name[commands[i]], e, frame

        seq_key = str(op.sequence)
        if not seq_key in smb2_ops:
            smb2_ops[seq_key] = []
        smb2_ops[seq_key].append(op)

read_stats = {}
write_stats = {}
fid_stats = {}
cmd_stats = [0 for x in range(19)]

seq_num = [int(x) for x in smb2_ops.keys()]
seq_num.sort()

count_cmd = 0
count_read = 0
count_write = 0

for i in seq_num:
    ## Command distribution
    command = smb2_ops[str(i)][0].command
    cmd_stats[command] += 1
    count_cmd += 1

    if command == smb2.SMB2_READ:
        k = str(smb2_ops[str(i)][0].read_length)

        if not k in read_stats:
            read_stats[k] = 0

        read_stats[k] += 1
        count_read += 1

    elif command == smb2.SMB2_WRITE:
        k = str(smb2_ops[str(i)][0].write_length)

        if not k in write_stats:
            write_stats[k] = 0

        write_stats[k] += 1
        count_write += 1

'''
    f = get_file_id(smb2_ops[i])
    if not f in fids:
        fids[f] = []
    fids[f].extend(smb2_ops[i])
'''

## Command Stats
print "\nTotal Requests = {0}".format(count_cmd)
print "             Command    Occurrence"
for k in range(len(cmd_stats)):
    print "{0:>20} => {1}".format(
        smb2.CommandName[k],
        cmd_stats[k])

## Read stats
rsizes = [int(x) for x in read_stats.keys()]
rsizes.sort()
print "\nTotal Read Requests = {0}".format(count_read)
print "   Bytes   Occurrences"
for i in rsizes:
    # print "{0:>8} => {1}".format(i, read_stats[str(i)])
    print "{0}, {1}".format(i, read_stats[str(i)])


## Write stats
wsizes = [int(x) for x in write_stats.keys()]
wsizes.sort()
print "\nTotal Write Requests = {0}".format(count_write)
print "   Bytes   Occurrences"
for i in wsizes:
    print "{0:>8} => {1}".format(i, write_stats[str(i)])
