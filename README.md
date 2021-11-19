# Dellicious

Dellicious is a tool for enabling/disabling LSA protection on arbitrary processes via a vulnerability in Dell's DBUtilDrv2.sys driver (version 2.5 or 2.7). If provided the driver, Dellicious installs it, exploits it, and then removes it. That obviously requires administrator access, but that's fairly normal for LSA Protect bypass techniques. See:

* [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) - LSA protect bypass using `rtcore.sys` (and a large influence on this project)
* [mimidrv](https://posts.specterops.io/mimidrv-in-depth-4d273d19e148) - Mimikatz kernel driver. LSA protect bypass by being a signed kernel driver :-D

LSA protection blocks memory access from other processes (a bit of an oversimplifaction but forgive me). When enabled lsass.exe can't have it's memory dumped by tools like mimikatz. Obviously, running mimikatz is extremely desirable for an attacker. Using this tool the attacker is able to disable the protection and dump/access memory.

Similarly, it may be desirable to enable memory protection on our own processes. So Dellicious exposes that functionality as well.

For more reading on LSA protection, I suggest the blog *[Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/)* by Clement Labro (the author of PPLDump).

## Where are the drivers?!

Rapid7 isn't comfortable redistributing the drivers. However, the required files have the following sha-1 hashes:

### dbutildrv2.sys version 2.5

* DBUtilDrv2.cat - [23bbc48543a46676c5cb5e33a202d261a33704fe](https://www.virustotal.com/gui/file/4b93fc56db034bfebb227b1e2af1b5e71cc663ffeffe3b59618f634c22db579d)
* dbutildrv2.inf - [c40ebb395cb79c3cf7ca00f59f4dc17930435fc5](https://www.virustotal.com/gui/file/4e2aa67daab4c4acac3d6d13490f93d42516fa76b8fda87c880969fc793a3b42)
* DBUtilDrv2.sys - [90a76945fd2fa45fab2b7bcfdaf6563595f94891](https://www.virustotal.com/gui/file/2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8)

### dbutildrv2.sys version 2.7

* DBUtilDrv2.cat - [06f2b629e7303ac1254b52ec0560c34d72b46155](https://www.virustotal.com/gui/file/c77c24e945acc73d6b723f60bcdc0330ff501eea34b7da95061101dd1120392a)
* dbutildrv2.inf - [19f8da3fe9ddbc067e3715d15aed7a6530732ab5](https://www.virustotal.com/gui/file/56ed7ff7299c83b307282ce8d1def51d72a3663249e72a32c09f6264348b1da2)
* DBUtilDrv2.sys - [b03b1996a40bfea72e4584b82f6b845c503a9748](https://www.virustotal.com/gui/file/71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009)
* WdfCoInstaller01009.dll - [c1e821b156dbc3feb8a2db4fdb9cf1f5a8d1be6b](https://www.virustotal.com/gui/file/3b9264416a78f5eab2812cd46b14f993815e9dbf5bd145b3876c2f0f93b98521)

## Example CLI Usage

In the following, lsass.exe is pid 736. I've instructed Dellicious to disable protection using DBUtilDrv2.sys version 2.7.

```
C:\Users\albinolobster\Desktop>.\dellicious.exe
option "pid" is required
Allowed options:
  -h, --help             produce help message
  -p, --pid arg          the target pid
  -e, --enable arg       enable memory protection (0 or 1)
  -d, --driver_path arg  The path to the driver inf, cat, and sys (and coinstaller)


C:\Users\albinolobster\Desktop>.\dellicious.exe -p 736 -e 0 -d C:\Users\albinolobster\Desktop\drivers\2_7\
[+] User provided pid: 736
[+] User provided driver directory: C:\Users\albinolobster\Desktop\drivers\2_7\
[+] Windows version found: 2009
[+] Using offsets:
        UniqueProcessIdOffset = 0x440
        ActiveProcessLinkOffset = 0x448
        SignatureLevelOffset = 0x878
[+] Attempting driver install...
[+] Driver installed!
[+] Device handle has been obtained @ \\.\DBUtil_2_5
[+] Ntoskrnl base address: fffff80229200000
[+] PsInitialSystemProcess address: ffffd00336c92180
[+] Target process address: ffffd00338c970c0
[+] Current SignatureLevel, SectionSignatureLevel, Type, Audit, and Signer bits (plus 5 bytes): 40c0000041083c
[+] Writing flags back as: 40c00000000000
[+] Done!
[+] Removing device
[!] Clean exit! o7
```

## Artifacts

This does leave artifacts on disk. Currently I don't clean up:

* Files in C:\Windows\Temp\
* Logging data in C:\Windows\INF\setupapi.dev
* DBUtilDrv2 service is left running (although it's in a bad / unusable state and will go away on reboot)
* DBUtilDrv2 is left in the driverstore
* I'm sure there are things in the event log that indicate driver installed / removed, etc.

## Credit

This codebase is heavily influenced by PPLKiller (mentioned above). It also was influenced by the dbutil_2_3.sys metasploit module as well as [Mitch Zakocs'](https://www.mitchellzakocs.com/blog/dbutil) write up on CVE-2021-21551.
