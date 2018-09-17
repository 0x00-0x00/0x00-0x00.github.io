---
layout: post
title:  "DLL Reversing - Writeup"
date:   2018-09-17 08:45:01 -0700
categories: writeup
---

Hello all, I am going to give a detailed write-up about how to reach flag in "DLL Reversing" challenge which was presented at CTF Fatec Ourinhos 2018 2nd edition.

# Challenge Information
Name: DLL Reversing

Download: [Link](http://s000.tinyupload.com/index.php?file_id=09369342402988039731)

---

# Initial Analysis

During the initial analysis, we need to determine which type of file this DLL fit. If it is C++ code, we should use a Debugger (like OllyDbg, x64dbg) to debug it, if it's a C# code, then it would be a .NET executable, which means we can decompile it to see source-code, which is always better for reversing!

## Determining file type

Using "file"  command, we are able to get that kind of information very quickly:
```bash
[root:~] file DLLReversing.dll 
DLLReversing.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

So it is a .NET assembly, which lead us to know that we are able to decompile it. We can use ILSpy, a .NET decompiler, to get our DLL source-code.

![Screenshot](/assets/dll-reversing-pic-01.JPG)

Reading source-code, we identify a Shellcode class. And it calls the following functions from Windows API:

* OpenProcess
* VirtualAllocEx
* VirtualProtectEx
* WriteProcessMemory
* CreateRemoteThread

Which means it is obviously injecting shellcode to a remote process. We can confirm that by reading the public function named Exec.

![Screenshot](/assets/dll-reversing-pic-02.JPG)

It decrypts an array of numbers using XOR on key 0x31 (49 decimal) and convert them to bytes - our shellcode in original format - and them searches for a process to open, then allocate memory, change memory permissions, write shellcode to remote process and finally creating a remote thread and pointing it to the begginning of shellcode.

We already know what the DLL is for, we must now execute it!

# Solving the challenge (Method 1)

There is two good ways of solving this challenge. One of them, and most easy, is to execute shellcode. We can use powershell for that.

![Screenshot](/assets/dll-reversing-pic-03.JPG)

You can see that we loaded the DLL in-memory and also that we are able to access Shellcode.Exec function directly from PowerShell terminal. Let's spawn a 32-bit Notepad and try to execute the Exec function.

![Screenshot](/assets/dll-reversing-pic-04.JPG)

This is by far the most easy solution. There is an alternate solution by reversing the shellcode to get flag. 

# Solving the Challenge (Method 2)

The shellcode in string (ASCII) format is the following:

```cmd
Çëô;|$(uáZ$ ëf KZ  ë  èD$ aÃ)ÔåÂhN ìRèÿÿÿE »~Øâs $Rèÿÿÿhll Ah32.dhuser0Û\$
æVÿU ÂP»¨¢M¼ $Rè_ÿÿÿhoxX hageBhMess1Û\$
ãhe}X hl3nghChalhion_hjecthL_Inhr_DLh0th3hf{4nhwgct1ÉL$&á1ÒRSQRÿÐ1ÀPÿU
```

You can look the flag in there, but to get it you will need to understand assembly.

Assembly pushes the string to the top of the stack before calling MessageBox, so we can just "simulate" how assembly would work to get the flag back.

Assembly code flag:
```cmd
hl3nghChalhion_hjecthL_Inhr_DLh0th3hf{4nhwgct
```

The "h" character is the PUSH assembly instruction, so we need to remove it every 4 bytes (because of 32-bit architecture), leading us to:

```cmd
l3ngChalion_jectL_Inr_DL0th3f{4nwgct
```

Now we pop 4 bytes from right to left.

wgct

f{4n

0th3

r_DL

L_In

ject

ion_

Chal

l3ng

e}


Which leads us to the flag:

wgctf{4n0th3r_DLL_Injection_Chall3nge}