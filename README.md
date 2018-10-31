# Description
Linux Log Cleaner

This tool is used to remove log traces.

`/var/run/utmp`, `/var/log/wtmp`, `/var/log/lastlog`.

# CookBook
## utmp
clear `/var/run/utmp` to hide your login info in command: `w`:
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-31-45.png)

then we want to hide the user: `macr0phag3`:
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-33-10.png)

result:
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-33-30.png)

## wtmp
clear `/var/log/wtmp` to hide your info in command: `last`.

just like `utmp`

## lastlog
tamper/clear the records in `/var/log/lastlog`.
you can use command: `lastlog` to check it out:
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-37-38.png)

![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-42-17.png)
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-42-29.png)

or just clear the record:
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-43-12.png)
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-43-22.png)

## others
```
usage: LLC.py [-h] -l {0,1,2} [-u USERNAME] [-i IP] [-t TTYNAME] [-f FILENAME]
              [-v {0,1,2}] [-m] [-mtime MTIME] [-mstime MSTIME] [-mtty MTTY]
              [-mip MIP]

optional arguments:
  -h, --help            显示帮助信息
  -l {0,1,2}, --log {0,1,2}
                        指定修改的日志文件。 [0:utmp]; 1:wtmp; 2:lastlog
  -u USERNAME, --username USERNAME
                        match records based on username
  -i IP, --ip IP        match records based on ip
  -t TTYNAME, --ttyname TTYNAME
                        match records based on ttyname
  -f FILENAME, --filename FILENAME
                        if log filename is not in ["utmp", "wtmp", "lastlog"],
                        give me the path and filename
  -v {0,1,2}, --verbose {0,1,2}
                        how much information you want: 0:silent; [1]; 2:debug
  -m, --mode            clear or modify? default: clear
  -mtime MTIME          assign time. if you want "1997-01-01 08:00:00", mtime
                        is 1997-01-01 08:00:00
  -mstime MSTIME        assign time. if you want "1997-01-01 08:00:00", mstime
                        is 0
  -mtty MTTY            assign ttyname, like: pts/1
  -mip MIP              assign ip, like: 192.168.1.1
```

just run `python LLC.py -h`

:P

# Version
The latest version: _2018.10.30 10:41:03_

# Dependencies
- Python

- ROOT :P
![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_21-46-34.png)

# TODO
- [x] `help list`. _2018.10.29 14:03_
- [x] fix the bug of lastlog. _2018.10.29 21:03_
- [X] `Print` func. _2018.10.29 22:03_
- [x] colored. _2018.10.29 22:10 PM_
- [x] compatible with py3.x. _2018.10.30 10:38:36_
- [x] verbose level 2. _2018.10.31 14:47:59_
- [x] replace "" with [empty]. _2018.10.31 14:53:57_
- [x] add func: tamper lastlog time. _2018.10.31 20:16:25_
- [x] add verbos level 0. _2018.10.31 20:30:23_
- [ ] README pics.
- [ ] add func: list all info
- [ ] LOGO
- [ ] tamper the logfile's modified date
