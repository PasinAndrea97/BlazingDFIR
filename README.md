# BlazingDFIR
<br>

![](https://i.imgur.com/aLirAZR.png)

<br>

An all in one powershell Tool to perform powerful remote Data Forensics Incident Response using WINRM!

# Components Decription <br>
1) .\tools\ --> this directory contains all the tools that will be uploaded to the remote machines involved in DFIR operations <br>
2) BlazingDFIR.ps1 --> Main Tool that enables you to execute accurate remote operations in an automated and secure manner using many available switches<br>

# Achieved Goals <br>
NF_Security achieved an amazing final result with BlazingDFIR: now a signle tool that speeds up all IR operations finally exists.
BlazingDFIR can gather as much data as possible with the Order of Volatility as principal rule that sets his execution and quality standards.

Gathered data follows this principle:

- Processor and processes: CPU, cache and register content, process state tables --> Already Achieved by BlazingDFIR
- Network: routing tables, ARP caches, process tables, kernel statistics --> Already Achieved by BlazingDFIR
- Main Memory --> Already Achieved by BlazingDFIR
- Semi Volatile Data: temporary files system / swap spaces --> Already Achieved by BlazingDFIR
- Resident Data: filesystem and slack space --> Achieved by <a href="https://github.com/Invoke-IR/PowerForensics">PowerForensics</a>
- Any Relevant Data --> There's always room for improvement, help us make BlazingDFIR better!

# How it works? <br>
The tool is meant to be simple and "Ready to Use". <br>
<b>**Every action made requires the user to input his INCIDENT RESPONSE account credentials for security reasons.</b>

1) To use the tool start by spawning an administrator powershell session that ignores "Execution Policies" using the following command <br>

```
powershell -ep bypass
```

<br>

2) Try to execute it without any argument to see the available switches <br>

```
.\BlazingDIFR.ps1
```

<br>

Output <br>

```
#################################################################################
# Written by: Nicolas Fasolo
# Name: BlazingDIFR.ps1
# email: nicolas.fasolo@hotmail.it
#
# Copyright NF_Security
#
#       Collects DIFR data from a specified host that the script will ask for
# ex: .\BlazingDIFR.ps1 -collect
#
#       Start DIFR process in a specified host that the script will ask for
# ex: .\BlazingDIFR.ps1 -target
#
#       Start DIFR process in a specified host list
# ex: .\BlazingDIFR.ps1 -list
#
#       Collects DIFR data from a specified host list
# ex: .\BlazingDIFR.ps1 -list -collect
#
#################################################################################


-remotetool "remotetool.exe/bat" | - Copies the .\tool directory to the remote machine and it executes the file you specified [EXE or BAT]
-getedp | - Gets Endpoint list (it will ask for Domain Controller Name) and generates .\EndpointList.txt
-collect | - Collects the DFIR directory in a specified remote host
-list | - Needed to specify the Endpoint list file
-cshare | - Creates the share C:\IR_DATA that will be used during DFIR operations
-target | - Target one Endpoint for DFIR operations
-autotarget | - Expects ./EndpointList.txt Target one Endpoint for automatic DFIR & Collect operations
-autolist | - Expects ./EndpointList.txt List to retrieve targets for automatic DFIR & Collect operations
```
<br>

3) To setup your local environment start the tool using the following switch <br>

```
.\BlazingDIFR.ps1 -cshare
```

<br> 

This step will create a local directory located in "C:\IR_Data" and share it with "everyone" permission <br>

Sample Output <br>

```
    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        08/02/2022     10:25                IR_Data

AvailabilityType      : NonClustered
CachingMode           : Manual
CATimeout             : 0
ConcurrentUserLimit   : 0
ContinuouslyAvailable : False
CurrentUsers          : 0
Description           :
EncryptData           : False
FolderEnumerationMode : Unrestricted
IdentityRemoting      : False
Infrastructure        : False
LeasingMode           : Full
Name                  : IR_Data
Path                  : C:\IR_Data
Scoped                : False
ScopeName             : *
SecurityDescriptor    : O:SYG:SYD:(A;;FA;;;WD)
ShadowCopy            : False
ShareState            : Online
ShareType             : FileSystemDirectory
SmbInstance           : Default
Special               : False
Temporary             : False
Volume                : \\?\Volume{fc90bbe4-0000-0000-0000-602200000000}\
PSComputerName        :
PresetPathAcl         : System.Security.AccessControl.DirectorySecurity

Local Share  C:\IR_Data\  has been created and shared correctly!
```

this step is crucial for Incident Response Operations, in fact it enables every incident responder to have public share where he can put / copy files for quick needings and to sotre DFIR data during operations.
<br>

<b>**Be careful! This directory could be seen from the attacker, so make sure you copy the critical files in a safe environment (way better if it is an external HD)</b>

<br>

4) Now it's time to understand the attacked infrastructure dimension. To help us the "-getedp" comes in our help! <br>

```
.\BlazingDIFR.ps1 -getedp
```
<br>

Sample Output <br>

```
Input the Incident Response Domain Admin Username: respondername_admin
Input the Incident Response Domain Admin Password: **************
Input Domain: CONTOSO
Retrieving Targets, please be patient...
Input your Domain Controller name: CONTOSODC1
186 Targets found
CONTOSODC00 CONTOSODC01 CONTOSODC03 CONTOSONotebook07 CONTOSOPC01 MEETINGROOM ...

The .\EndpointList.txt file has been imported successfully

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  3 WinRM3          CONTOSOC1          RemoteMachine   Disconnected  Microsoft.PowerShell          None
```
<br>

at this point you should have a file named ".\EndpointList.txt" inside the directory where the Tool is placed. You can use it with "-auto*" switches or just to have a deeper understanding about the infrastructure you're working in.

<br>

![](https://i.imgur.com/nv9eX8G.png)

<br>

5) Start a remote data collection activity by using the "-target" switch <br>

```
.\BlazingDIFR.ps1 -target
```
<br>

Sample Output <br>

```
Input the Incident Response Domain Admin Username: respondername_admin
Input the Incident Response Domain Admin Password: **************
Input Domain: CONTOSO


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        08/02/2022     10:19                IR_Data

AvailabilityType      : NonClustered
CachingMode           : Manual
CATimeout             : 0
ConcurrentUserLimit   : 0
ContinuouslyAvailable : False
CurrentUsers          : 0
Description           :
EncryptData           : False
FolderEnumerationMode : Unrestricted
IdentityRemoting      : False
Infrastructure        : False
LeasingMode           : Full
Name                  : IR_Data
Path                  : C:\IR_Data
Scoped                : False
ScopeName             : *
SecurityDescriptor    : O:SYG:SYD:(A;;FA;;;WD)
ShadowCopy            : False
ShareState            : Online
ShareType             : FileSystemDirectory
SmbInstance           : Default
Special               : False
Temporary             : False
Volume                : \\?\Volume{fc90bbe4-0000-0000-0000-602200000000}\
PSComputerName        :
PresetPathAcl         : System.Security.AccessControl.DirectorySecurity

Input your taget Endpoint name: CONTOSODC1
Starting comprehensive autoruns collection for all users...
Success!

I'm waiting to let memory acquisition process end successfully...
79 seconds left
78 seconds left
77 seconds left
76 seconds left
75 seconds left
...
Starting to compress payload... Hold on...
Payload Compessed, you can use -collect switch to retrieve data from  CONTOSODC1

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  4 WinRM4          CONTOSODC1          RemoteMachine   Disconnected  Microsoft.PowerShell          None

```
<br>
You will end up with a zipped file like the following one<br>

<br>

![](https://i.imgur.com/zCwRSSa.png)

<br>

![](https://i.imgur.com/A30U7SV.png)

<br>

Same thing applies to the "-auto*" switches that will perform the same actions that "-target" & "-collect" do but using as targets the endpoints listed in ".\EndpointList.txt" file if present.

# Setup Diagram <br>

![](https://i.imgur.com/uIDk80u.png)

# Network Implementation Example <br>
<br>

<b>In the next picture you can see how easy can be to reach all WINRM activated hosts by using this tool in any device on the same corporate network.<b/>
   No matter how complex the company can be, you can ZAP every host your landing machine can reach! <b/>

<br>

![](https://i.imgur.com/dRQ230a.png)

