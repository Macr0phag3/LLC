# -*- coding:utf-8 -*-

import struct
import pwd
import argparse
import sys
import time


def compare(a, b):
    return a == b or a == None


def match_xtmp():
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
            print("[*]found matched log in "+FILENAME)
            for i in matched:
                print(i)
            if raw_input("[?]clean them? [y]/n > ") != "n":
                return xtmp
            else:
                print("  [!]aborted")
        else:
            print("[*]not found!")

    except Exception as e:
        Print('match log: %s falied\n%s' % (FILENAME, str(e)), level=0)


def clear_log(contents):
    try:
        with open(FILENAME, 'w+b') as fp:
            fp.write(contents)
        Print("  [-]success!", level=0)
    except Exception as e:
        Print('  [-]clear log: %s falied\n%s' % (FILENAME, str(e)), level=0)


def match_lastlog():
    try:
        pw = pwd.getpwnam(USERNAME)
    except:
        print("[*]not found!")
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
            print("[*]found matched log in "+FILENAME)
            for i in matched:
                print(i)
            if raw_input("[?]clean them? [y]/n > ") != "n":
                return lastlog
            else:
                print("  [!]aborted")
        else:
            print("[*]not found!")
    except Exception as e:
        Print('match log: %s falied\n%s' % (FILENAME, str(e)), level=0)


def Print(msg, level):
    print(msg)


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
parser.add_argument('-m', '--mode', default=0, type=int,
                    choices=[0, 1, 2], help='[0:utmp]; 1:wtmp; 2:lastlog')

parser.add_argument('-f', '--filename')

parser.add_argument('-u', '--username')
parser.add_argument('-i', '--ip')
parser.add_argument('-t', '--ttyname')

parser.add_argument('-v', '--verbose', default=1, type=int,
                    choices=[0, 1, 2], help='0:silent; [1]; 2:debug')


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
        sys.exit("give me a username or ip or ttyname")

    # 0: change command: last
    # 1: change command: lastlog
    new_data = match_xtmp()
    if new_data != None:
        clear_log(new_data)
else:
    # 2: change command: w
    if not USERNAME:
        sys.exit("give me a username")

    new_data = match_lastlog()
    if new_data != None:
        clear_log(new_data)

