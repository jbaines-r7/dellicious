# Dellicious

Dellicious is a tool for enabling/disabling LSA protection on arbitrary processes via a vulnerability in Dell's DBUtilDrv2.sys driver (version 2.5 or 2.7). Dellicious drops the vulnerable driver to disk, installs it, exploits it, and then removes it. That obviously requires administrator access, but that's fairly normal for LSA Protect bypass techniques. See:

* [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) - LSA protect bypass using `rtcore.sys`
* [PPLDump](https://github.com/itm4n/PPLdump) - LSA protect bypass using `DefineDosDevice` and known dlls
* [mimidrv](https://posts.specterops.io/mimidrv-in-depth-4d273d19e148) - Mimikatz kernel driver. LSA protect bypass by being a signed kernel driver :-D

LSA protection blocks memory access from other processes (a bit of an oversimplifaction but forgive me). When enabled lsass.exe can't have it's memory dumped by tools like mimikatz. Obviously, running mimikatz is extremely desirable for an attacker. Using this tool the attacker is able to disable the protection and dump/access memory.

Similarly, it may be desirable to enable memory protection on our own processes. So Dellicious exposes that functionality as well.

For more reading on LSA protection, I suggest the blog *[Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/)* by Clement Labro (the author of PPLDump).

## Example GIF

Oh no. It's too big to host on github :(

## Example CLI Usage

In the following, lsass.exe is pid 740. I've instructed Dellicious to disable protection using DBUtilDrv2.sys version 2.7.

```
C:\Users\albinolobster\Desktop>.\dellicious.exe -p 740 -e 0 -d 1
[+] User provided pid: 740
[+] Windows version found: 2009
[+] Using offsets:
        UniqueProcessIdOffset = 0x440
        ActiveProcessLinkOffset = 0x448
        SignatureLevelOffset = 0x878
[+] Dropping version 2.7 to disk
[+] Attempting driver install...
[+] Driver installed!
[+] Device handle has been obtained @ \\.\DBUtil_2_5
[+] Ntoskrnl base address: fffff80615c00000
[+] PsInitialSystemProcess address: ffffa20e29860180
[+] Target process address: ffffa20e2b3e10c0
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
