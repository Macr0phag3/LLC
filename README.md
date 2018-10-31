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



# Version
The latest version: _2018.10.30 10:41:03_

# Dependencies
Python
ROOT :P
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
