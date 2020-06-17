---
layout: post
title:  "Decrypting any .DEC files on HackNet game"
date:   2020-17-06 00:00:00 -0300
categories: games
---


# Introduction
Hello all, It's been over a year that I have not given attention to this blog. As usual, I am worried about other many things happening in my life, but a few weeks ago, while I trying to get over a mission in "_HackNet_" - a fun "_hacking_" simulator game - I got a bug.


![103319113a2b08ea71b3871345ce0319.png](/assets/8edccf6c0ee14edc8ec469cbaf162374.png)

Googling around for a while and I didn't find any information about this. I don't even know if this is intended or not, but apparently this is a bug. Some forums on the internet imply that after the "_DECHead.exe_" usage it should spill out some information and not an error.

# The journey begins

I got intrigued by this so much, that I had to try to reverse the game to try to find a solution for this.

To my luck, the game code is written in C#, so it's a breeze to decompile it with any decompiler and get almost fully readable code.

Fuzzing around the game code for a moment, and found the encryption function that are used for the files.

![5643c1ce8951d08cea32528aaf7fe19a.png](/assets/5b11c8feae0748f29e6b9f3ea3416d9e.png)

The picture above says that "_Encrypt_" function returnas a string datatype, but most importantly, it uses a string variable named "data" and a unsigned short integer named as "pass" variable.

In other words, the "_pass_" is the encryption key, and as we all know, unsigned short integers are as they name say they are.... "_short_".

The game have only 65536 possibilities to use as encryption key, ranging from 0 to 65535, and this is quickly brute-forceable.

# Decrypting my own encrypted text

With this in mind, I coded a encryptor/decryptor that uses the same algorithm as the game. This way, I could PoC how easily it is to decode plaintext data from these "_encrypted_" files.

![811b39d69a04ab3b1c3a0749457f1f04.png](/assets/cf96cdcb29ba4936be04e4aa21d1eaef.png)


At the first time I tested the decryptor, it found a "fake" key, but as soon I ignored all decryption results that were not ASCII and have not any space character in it, it could then find the real key.

![6c4d5f10a8313618be3eecdd41026a1f.png](/assets/b2bd2582c25b4bbdb490f02d4846856c.png)

# Decrypting files are not enough

After this decryption worked, I had success decrypting any file I had over my save game file. Thus, "_hacking the hacking game achievement_" was achieved.

But this was not enough to bypass my bug on DECHead.exe and continue my gameplay, as I discovered that aside from encrypting file data, the .DEC file headers also contained the IP information of the computer that used the used the program to "_protect_" the files. And I needed the IP information to continue the story.

With a little more footwork on reversing, I got success also in this aspect, and now I could not only crack all .DEC files from Hacknet, but also know which IP encrypted it. Which allowed me to access a lot of servers that I think it might not be possible to know it playing legit.


![3c8d02365be4daa4ef774107679f60f7.png](/assets/f9d577de375d4654acafcdc15ee2ca5d.png)

This is the end! With this, I was able to bypass that error that was stopping me from using DECHead.exe and got success to continue the story of the game.

If you reached here, thanks for reading. If you ever have any problem on HackNet like I did and need this code to get over with, email me and I can share the code.

Best regards, 

zc00l.




