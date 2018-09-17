---
layout: post
title:  "PowerShell Ransomware - Writeup"
date:   2018-09-17 11:53:01 -0700
categories: writeup
---


# Introduction

This is the write-up for PowerShell Ransomware, a CTF challenge presented at CTF Fatec Ourinhos 2018 2nd edition.

# Challenge Information
Name: PowerShell Ransomware

Description: The flag has been taken for ransom. But I got the source-code, maybe you can decrypt it?

---

# Analysis

Look at the following source-code:

```powershell
function AllYourFilesAreBelongToMe
{
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$EncryptionKey
    )

    Get-ChildItem .\flag.txt | % { 
        $EncryptedData = "";
        (Get-Content -Encoding ASCII $_.FullName).ToCharArray() | % {
            $EncryptedData += [char]($_ -bxor $EncryptionKey)
   
        }
        Set-Content -Path $_.FullName -Value $EncryptedData
        Write-Output "All Your Files Are Belong To Me Now!"
    }
}
```

This takes a number (key) named $EncryptionKey and uses XOR to "encrypt" a file content. Let's modify this script so we can use it against itself.

```powershell
function AllYourFilesAreBelongToMe
{
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$EncryptionKey
    )

    Get-ChildItem .\flag.txt | % { 
        $EncryptedData = "";
        (Get-Content -Encoding ASCII $_.FullName).ToCharArray() | % {
            $EncryptedData += [char]($_ -bxor $EncryptionKey)
   
        }
        Write-Output $EncryptedData
    }
}
```

As you can see, I removed the last two lines from function and used Write-Output to __show us the content of the encrypted data instead of overwriting the file content__. Now load our code to a PowerShell terminal: 

![Screenshot](/assets/posh-pic-03.JPG)

 As you already might know, if you XOR something with a single byte key, you can reveal it's original content by XORing the encrypted value against the same key. 

We must now brute-force against 255 and below numbers, because it is impossible to be bigger than 255 (because a single byte XOR key is used).

Looping from 255 to 0, we are able to XOR against all possible keys:

![Screenshot](/assets/posh-pic-04.JPG)

And scrolling down a little more, we get our flag on $EncryptionKey 51!

![Screenshot](/assets/posh-pic-05.JPG)
