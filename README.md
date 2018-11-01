# Description
Linux Log Cleaner

![](https://raw.githubusercontent.com/Macr0phag3/LLC/master/pics/2018-10-31_22-33-25.png)

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
              [-d] [-m] [-mtime MTIME] [-mstime MSTIME] [-mtty MTTY]
              [-mip MIP]

optional arguments:
  -h, --help            显示帮助信息
  -l {0,1,2}, --log {0,1,2}
                        指定修改的日志文件。 [0:utmp]; 1:wtmp; 2:lastlog
  -u USERNAME, --username USERNAME
                        根据用户名匹配记录
  -i IP, --ip IP        根据 ip 匹配记录
  -t TTYNAME, --ttyname TTYNAME
                        根据 tty 匹配记录
  -f FILENAME, --filename FILENAME
                        如果日志文件不在正常的位置或者不是正常的名字，需要给出具体的路径（包括文件名）
  -d, --debug           调试模式会输出一些详细的东西。
  -m, --mode            默认为清空操作，加了此参数为修改操作（仅用于 lastlog）
  -mtime MTIME          **仅在操作 lastlog 时使用** 指定修改后的时间。时间格式为："1997-01-01 08:00:00"
  -mstime MSTIME        **仅在操作 lastlog 时使用** 指定修改后的。时间格式为：时间戳
  -mtty MTTY            **仅在操作 lastlog 时使用** 指定修改后的 tty：pts/1
  -mip MIP              **仅在操作 lastlog 时使用** 指定修改后的 ip：192.168.1.1
```

just run `python LLC.py -h`

:P

# Version
The latest version: _2018.10.30 10:41:03_

# Dependencies
- Py 2 or 3

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
- [x] README pics. _2018.10.31 22:03:49_
- [x] LOGO. _2018.10.31 22:25:00_
- [ ] ~~add func: list all info~~
- [ ] tamper the logfile's modified date
