#################################################################################
# Written by: Nicolas Fasolo 
# Name: BlazingDIFR.ps1
# email: nicolas.fasolo@hotmail.it
#
# Copyright NF_Security
#
#	Collects DIFR data from a specified host that the script will ask for
# ex: .\BlazingDIFR.ps1 -nolist -collect
#
#	Start DIFR process in a specified host that the script will ask for
# ex: .\BlazingDIFR.ps1 -nolist
#
#	Start DIFR process in a specified host list
# ex: .\BlazingDIFR.ps1 -list Endpointlist.txt
#
#	Collects DIFR data from a specified host list
# ex: .\BlazingDIFR.ps1 -list Endpointlist.txt -collect
#
#################################################################################
#ARGS
param(		
		[string]$remoteTool, #Copy the ".\tool" directory to the remote machine and execute the file you specify
		[switch]$list, #Expects ./EndpointList.txt List to retrieve targets for DFIR operations		
		[switch]$target, #Target one Endpoint for DFIR operations
		[switch]$cshare, #using "-cshare" creates the share that will be used during DFIR
		[switch]$getedp, #using "-getedp" set the script in "Get Endpoints" mode
		[switch]$collect, #using "-collect" set the script in "Collector Mode"
		[switch]$autotarget, # Target one Endpoint for automatic DFIR & Collect operations
		[switch]$autolist #Expects ./EndpointList.txt List to retrieve targets for automatic DFIR & Collect operations
	 ) 

###### DFIR FUNCTIONS ######
# This section contains the functions used inside main routines

function Compute-FileHash {
Param(
    [Parameter(Mandatory = $true, Position=1)]
    [string]$FilePath,
    [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
    [string]$HashType = "MD5"
)
    
    switch ( $HashType.ToUpper() )
    {
        "MD5"       { $hash = [System.Security.Cryptography.MD5]::Create() }
        "SHA1"      { $hash = [System.Security.Cryptography.SHA1]::Create() }
        "SHA256"    { $hash = [System.Security.Cryptography.SHA256]::Create() }
        "SHA384"    { $hash = [System.Security.Cryptography.SHA384]::Create() }
        "SHA512"    { $hash = [System.Security.Cryptography.SHA512]::Create() }
        "RIPEMD160" { $hash = [System.Security.Cryptography.RIPEMD160]::Create() }
        default     { "Invalid hash type selected." }
    }

    if (Test-Path $FilePath) {
        $File = Get-ChildItem -Force $FilePath
        $fileData = [System.IO.File]::ReadAllBytes($File.FullName)
        $HashBytes = $hash.ComputeHash($fileData)
        $PaddedHex = ""

        foreach($Byte in $HashBytes) {
            $ByteInHex = [String]::Format("{0:X}", $Byte)
            $PaddedHex += $ByteInHex.PadLeft(2,"0")
        }
        $PaddedHex
        $File.LastWriteTimeUtc
        $File.Length
        
    } else {
        "${FilePath} is locked or could not be found."
        "${FilePath} is locked or could not be not found."
        Write-Error -Category InvalidArgument -Message ("{0} is locked or could not be found." -f $FilePath)
    }
}

function GetShannonEntropy {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [string]$FilePath
)
    $fileEntropy = 0.0
    $FrequencyTable = @{}
    $ByteArrayLength = 0
            
    if(Test-Path $FilePath) {
        $file = (ls $FilePath)
        Try {
            $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
        } Catch {
            Write-Error -Message ("Caught {0}." -f $_)
        }

        foreach($fileByte in $fileBytes) {
            $FrequencyTable[$fileByte]++
            $ByteArrayLength++
        }

        $byteMax = 255
        for($byte = 0; $byte -le $byteMax; $byte++) {
            $byteProb = ([double]$FrequencyTable[[byte]$byte])/$ByteArrayLength
            if ($byteProb -gt 0) {
                $fileEntropy += -$byteProb * [Math]::Log($byteProb, 2.0)
            }
        }
        $fileEntropy
        
    } else {
        "${FilePath} is locked or could not be found. Could not calculate entropy."
        Write-Error -Category InvalidArgument -Message ("{0} is locked or could not be found." -f $FilePath)
    }
}

function DeploynExec {
			param(				
				$_endpointName,
				$_toolFullNameWithExt
			)
			$_toolFullPath = -join(".\tools\", $_toolFullNameWithExt);
			$_toolExists = Test-Path $_toolFullPath;
			if($_toolExists -eq $true)
			{
				#Remote PSSession Establishment
				$RemoteSession = New-PSSession -Computername $_remoteEdp -Credential $_secureCreds;			
				#Tools Copying
				Copy-Item -ToSession $RemoteSession -Recurse -Path ".\tools" -Destination "C:\";
				#Deletes Remote Directories & Files
				Invoke-Command -Session $RemoteSession -ArgumentList $_toolFullNameWithExt -Scriptblock {
				param($_toolFullNameWithExt);
				$_toolPath = -join("C:\tools\", $_toolFullNameWithExt);
				#ToolExec with args if needed		
				Start-Process -NoNewWindow -FilePath $_toolPath -ArgumentList ("");			
				};
			
				#Disconnect & Rmeove Sessions
				Get-PSSession | Disconnect-PSSession;
				Get-PSSession | Remove-PSSession;
			}
			else
			{
				Write-Host "Cannot find tool in " $_toolFullPath;
			}
}


##############################
###### Core FUNCTIONS Routines ######

function DIFRHost {

			param (
				$_endpointName
			)

			$_remoteEdp = $_endpointName;
			#Collection ZIP File
			$_dataToExtract = -join("C:\", $_remoteEdp, ".zip");
			$_localEdpPath = -join($_localPath, $_remoteEdp); #Path Variable
			#Remote PSSession Establishment
			#wmic /node:$_endpointName process call create "winrm quickconfig" -Credential $_secureCreds
			#wmic /node:$servername share list brief -Credential $_secureCreds
			$RemoteSession = New-PSSession -Computername $_remoteEdp -Credential $_secureCreds;
			#$_dfirSharePath = -join("\\", $_serverIp, "\IR_Data\"); #PATH per RemoteDir	
			$_localPathsExists = Test-Path  $_localEdpPath;
			
			#Tools Copying
			Copy-Item -ToSession $RemoteSession -Recurse -Path ".\tools" -Destination "C:\";
						
			Invoke-Command -Session $RemoteSession -ArgumentList $_dataToExtract -Scriptblock {	
			param($_dataToExtract); # Param to pass local script var into invoke-command
			$_DFIRPathExists = Test-Path  "C:\DFIR";
			if($_DFIRPathExists -eq $false)
			{
				New-Item -ItemType Directory -Force -Path "C:\DFIR";
			}
			$_DFIRFileExists = Test-Path  $_dataToExtract;
			if($_DFIRFileExists -eq $true)
			{
				Remove-Item -Recurse -Force $_dataToExtract;
			}	
			
			#MEMORY ACQUISITION			
			Start-Process -NoNewWindow -FilePath "C:\tools\winpmem_mini_x64_rc2.exe" -ArgumentList ("C:\DFIR\" + $env:computername + ".raw");
			
			#AUTORUNS SECTION
			Write-Host "Starting comprehensive autoruns collection for all users...";	
			Start-Process -NoNewWindow -FilePath "C:\tools\autoruns_collector.bat";		
			Write-Host "Success!";	
			#Wait time SECTION
			Write-Host "I'm waiting to let memory acquisition process end successfully...";		
			$_sleepTime = 80;
			DO
			{
				Start-Sleep -s 1;
				$_sleepTime = $_sleepTime - 1;
				Write-Host $_sleepTime "seconds left";
			}while($_sleepTime -gt 0)
			
			
			#ENUMERATION SECTION			
			wmic share list brief > C:\DFIR\SharesList.txt;
			wmic process list >  C:\DFIR\ProcessList.txt;
			wmic ntdomain list >  C:\DFIR\NtdomainList.txt;
			wmic useraccount list >  C:\DFIR\UseraccountList.txt;
			wmic group list >  C:\DFIR\DomaingroupsList.txt;
			wmic sysaccount list >  C:\DFIR\SysaccountList.txt;
			try
			{
				wmic /namespace:\\root\securitycenter2 path antivirusproduct get * /value > C:\DFIR\AVproductsSecCenter.txt;
			}
			catch
			{
				Write-Host "The target does not have SecurityCenter2 --> Probably it is a server, no antivirus data available!"
			}
			wmic USERACCOUNT get "Domain,Name,Sid" > C:\DFIR\LocalUsersAccounts.txt;
			
			Write-Host "Starting to compress payload... Hold on...";
			$completed = $false;			
			DO
			{
				try{
					#Compress-Archive -Path C:\Enumeration.txt -Update -DestinationPath $_dataToExtract;	
					#Creates NetFramework 4.5 method to compress files larger than 2 GB
					Add-Type -AssemblyName System.IO.Compression.FileSystem; #NET FRAMEWORK Reference	
					[IO.Compression.ZipFile]::CreateFromDirectory("C:\DFIR",$_dataToExtract, [IO.Compression.CompressionLevel]::Optimal, $true, [Text.Encoding]::Default);
					$completed = $true;
					Write-Host "Payload Compessed, you can use -collect swtich to retrieve data from " $env:computername;
				}
				catch
				{
					$completed = $false;
					Write-Host "Payload Compession failed, I'll retry in 5 seconds";
					Write-Host $_;
					Start-Sleep -s 5;
				}
			}while($completed -eq $false)
			
		};
		
		
		#Disconnect & Rmeove Sessions
		Get-PSSession | Disconnect-PSSession;
		Get-PSSession | Remove-PSSession;
}

function GetEndpoints {
	param (
				$_endpointName
			)
	$_remoteEdp = $_endpointName;
	$_dataToExtract = -join("C:\", $_remoteEdp, ".zip");
	$RemoteSession = New-PSSession -Computername $_remoteEdp -Credential $_secureCreds;
	Invoke-Command -Session $RemoteSession -ArgumentList $_dataToExtract -Scriptblock {
				param($_dataToExtract);				
				$_DFIRPathExists = Test-Path  "C:\DFIR";
				
				if($_DFIRPathExists -eq $false)
				{
					New-Item -ItemType Directory -Force -Path "C:\DFIR";
				}
				if($LastLogonLessThanDaysAgo -gt 0)
				{
					$today = Get-Date
					$cutoffdate = $today.AddDays(0 - $LastLogonLessThanDaysAgo)
					$targets = Get-ADComputer -Filter {(LastLogonDate -gt $cutoffdate)} -Properties Name #-SearchBase $ActiveDirectorySearchBase
				}
				else
				{
					$targets = Get-ADComputer -Filter {(LastLogonDate -gt 0)} -Properties Name #-SearchBase $ActiveDirectorySearchBase
				}

				$real_targets = New-Object System.Collections.ArrayList

				foreach ($tgt in $targets)
				{
					if ($tgt.Name -match $HostnameRegex){
						[void]$real_targets.Add($tgt.Name)
					}
				}

				if($Randomize){ $real_targets = $real_targets | Sort-Object {Get-Random} }

				if($outfile)
				{
					$real_targets | out-file "$PSScriptRoot\$outfile" 
					Write-Host "$($real_targets.Count) Targets found"
					Write-Host "List saved to: $PSScriptRoot\$outfile"
					Write-Host "All Done!"
				}else
				{
					Write-Host "$($real_targets.Count) Targets found"
					$real_targets | out-file "C:\DFIR\EndpointList.txt";
					Write-Host $real_targets
				}		
				
				#Creates NetFramework 4.5 method to compress files larger than 2 GB
				Add-Type -AssemblyName System.IO.Compression.FileSystem; #NET FRAMEWORK Reference					
				[IO.Compression.ZipFile]::CreateFromDirectory("C:\DFIR",$_dataToExtract, [IO.Compression.CompressionLevel]::Optimal, $true, [Text.Encoding]::Default);				
				
			};
			
			#EndpointList.txt LocalCopy
			Copy-Item -FromSession $RemoteSession -Path "C:\DFIR\EndpointList.txt" -Destination ".\EndpointList.txt";
			Write-Host "The .\EndpointList.txt file has been imported successfully";
			Start-Process ".\EndpointList.txt";
		#Disconnect & Rmeove Sessions
		Get-PSSession | Disconnect-PSSession;
		Get-PSSession | Remove-PSSession;
		
		
}

function CollectData {
	param (
				$_endpointName
			)
	$_remoteEdp = $_endpointName;
			#Collection ZIP File
			
			$_dataToExtract = -join("C:\", $_remoteEdp, ".zip");
			$_localEdpPath = -join($_localPath, $_remoteEdp, ".zip"); #Path Variable
			$_localPathsExists = Test-Path  $_localEdpPath;
			#Remote PSSession Establishment
			# wmic /node:$servername process call create "winrm quickconfig" -Credential $_secureCreds
			# wmic /node:$servername share list brief -Credential $_secureCreds
			$RemoteSession = New-PSSession -Computername $_remoteEdp -Credential $_secureCreds;
			#$_dfirSharePath = -join("\\", $_serverIp, "\IR_Data\"); #PATH per RemoteDir		
			
			#Result Retrieve		
			Copy-Item -FromSession $RemoteSession -Path $_dataToExtract -Destination $_localEdpPath;
			Write-Host "DFIR data has been saved successfully! You can find it in " $_localEdpPath;
			#Deletes Remote Directories & Files
			Invoke-Command -Session $RemoteSession -ArgumentList $_dataToExtract -Scriptblock {
			param($_dataToExtract);
			Remove-Item -Recurse -Confirm:$false -Force  "C:\tools\"; #Delete ToolsDir
			Remove-Item -Confirm:$false -Force $_dataToExtract; #Delete Zipped Data
			Remove-Item -Recurse -Confirm:$false -Force "C:\DFIR\"; #Delete Directory
			Write-Host "All remote DFIR tools and DIRS were removed successfully!"
			};
		
			#Disconnect & Rmeove Sessions
			Get-PSSession | Disconnect-PSSession;
			Get-PSSession | Remove-PSSession;
			#Open Direcotry In Explorer
			Invoke-Item $_localEdpPath;
}

##############################
if (($collect -eq $false) -and
	($list -eq $false) -and
	($target -eq $false) -and
	($cshare -eq $false) -and
	($getedp -eq $false) -and
	($collect -eq $false) -and
	($autotarget -eq $false) -and
	($autolist -eq $false) -and
	($remoteTool.Length -lt 3)
	)
{
	$Modules = @"

#################################################################################
# Written by: Nicolas Fasolo 
# Name: BlazingDIFR.ps1
# email: nicolas.fasolo@hotmail.it
#
# Copyright NF_Security
#
#	Collects DIFR data from a specified host that the script will ask for
# ex: .\BlazingDIFR.ps1 -collect
#
#	Start DIFR process in a specified host that the script will ask for
# ex: .\BlazingDIFR.ps1 -target
#
#	Start DIFR process in a specified host list
# ex: .\BlazingDIFR.ps1 -list
#
#	Collects DIFR data from a specified host list
# ex: .\BlazingDIFR.ps1 -list -collect
#
#################################################################################


-RemoteExecuteTool | - Copy the .\tool directory to the remote machine and execute the file you specify [EXE or BAT]
-getedp | - Gets Endpoint list (it will ask for Domain Controller Name) and generates .\EndpointList.txt
-collect | - Collects the DFIR directory in a specified remote host
-list | - Needed to specify the Endpoint list file
-cshare | - Creates the share C:\IR_DATA that will be used during DFIR operations
-target | - Target one Endpoint for DFIR operations
-autotarget | - Expects ./EndpointList.txt Target one Endpoint for automatic DFIR & Collect operations
-autolist | - Expects ./EndpointList.txt List to retrieve targets for automatic DFIR & Collect operations

"@;

Clear-Host;
Write-Host $Modules;
Exit;
}
#Local EndpointData (Pref Domain Controller)
$ipV4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address;
$_serverIp =  $ipV4.IPAddressToString; #IP local endpoint
$_serverName = $env:computername; #FQDN local endpoint
#DFIR Share (Locally created)
$_localPath = "C:\IR_Data\";
#Auth Data
$_username = Read-Host -Prompt 'Input the Incident Response Domain Admin Username'; #USERNAME
$_securePassword = Read-Host -Prompt 'Input the Incident Response Domain Admin Password' -AsSecureString; #PASSWORD
$_domain = Read-Host -Prompt 'Input Domain'; #"DOMAINNAME"
$_secureCreds = New-Object System.Management.Automation.PSCredential($_username, $_securePassword );

if($cshare -eq $true)
{
	#Test Directories
	$_pathsExists = Test-Path  $_localPath;

	#Create Directories if $_pathsExists returns $false
	if($_pathsExists -eq $false)
	{
		New-Item -ItemType Directory -Force -Path $_localPath;	
		#Share Base Directory and set IR USER full control
		$UserId = "Everyone"; #$_domain +"\" + $_username
		New-SmbShare -Path $_localPath -Name IR_Data -FullAccess $UserId;
		$Acl = Get-Acl $_localPath;
		$NewAccessRule = New-Object system.security.accesscontrol.filesystemaccessrule("Everyone","FullControl","Allow");
		$Acl.SetAccessRule($NewAccessRule);
		Set-Acl $_localPath $Acl;
		Write-Host "Local Share " $_localPath  " has been created and shared correctly!";
	}
	else
	{
		Write-Host "Local Share " $_localPath  " already exists!";
	}
}
if(($remoteTool -Match ".exe") -Or ($remoteTool -Match ".bat"))
{
	DeploynExec $remoteTool;
}
if($autotarget -eq $true)
{
	#Asks for Host name
	$_remoteEdp = Read-Host -Prompt 'Input your taget Endpoint name';
	DIFRHost $_remoteEdp;
	Write-Host "I'm waiting 10 second before proceeding with data collection";
	Start-Sleep -s 10;
	CollectData $_remoteEdp;
}

if($autolist -eq $true)
{
	Write-Host "TODO - Remote DFIR into list foreach endpoint";
	$_EdpList = ".\EndpointList.txt";
	$_listExists = Test-Path $_EdpList;
	Write-Host $_EdpList;
	if($_listExists -eq $true)
	{
		foreach($line in [System.IO.File]::ReadLines($_EdpList))
		{				
			DIFRHost $line;
			Write-Host "I'm waiting 10 second before proceeding with data collection";
			Start-Sleep -s 10;
			CollectData $line;
		}		
	}
	else
	{
		Write-Host ".\EndpointList.txt does not exists! Run tool with the -getedp argument";
	}
}

if($getedp -eq $true)
{
	Write-Host "Retrieving Targets, please be patient..."
	#Asks for Domain Controller Host name
	$_remoteEdp = Read-Host -Prompt 'Input your Domain Controller name';
	GetEndpoints $_remoteEdp;
	
}
#Single Host script Execution
if($target -eq $true)
{
	#Asks for Host name
	$_remoteEdp = Read-Host -Prompt 'Input your taget Endpoint name';
	DIFRHost $_remoteEdp;
}
if(($collect -eq $true) -and ($list -eq $false))
{
	#Asks for Host name
	$_remoteEdp = Read-Host -Prompt 'Input your taget Endpoint name';
	CollectData $_remoteEdp;
}
if (($collect -eq $false) -and ($list -eq $true))
{
	Write-Host "TODO - Remote DFIR into list foreach endpoint";
	$_EdpList = ".\EndpointList.txt";
	$_listExists = Test-Path $_EdpList;
	Write-Host $_EdpList;
	if($_listExists -eq $true)
	{
		foreach($line in [System.IO.File]::ReadLines($_EdpList))
		{	
			Write-Host "Doing stuff in target " $line;
			DIFRHost $line;			
		}		
	}
	else
	{
		Write-Host ".\EndpointList.txt does not exists! Run tool with the -getedp argument";
	}
}
if (($list -eq $true) -and ($collect -eq $true))
{
	Write-Host "TODO - Remote Collect into list foreach endpoint";
	$_EdpList = ".\EndpointList.txt";
	$_listExists = Test-Path $_EdpList;
	if($_listExists -eq $true)
	{
		foreach($line in [System.IO.File]::ReadLines($_EdpList))
		{
		    CollectData $line;
		}		
	}
	else
	{
		Write-Host ".\EndpointList.txt does not exists! Run tool with the -getedp argument";
	}
}
















<#

### OS Specifics ###
wmic os LIST Full
wmic computersystem LIST full
### Peripherals ###
wmic path Win32_PnPdevice 
### Installed Updates ###
wmic qfe list brief
### Directory Listing and File Search ###
wmic DATAFILE where "path='\\Users\\test\\Documents\\'" GET Name,readable,size
wmic DATAFILE where "drive='C:' AND Name like '%password%'" GET Name,readable,size /VALUE
### Local User Accounts ###

### Domain and DC Info ###
wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles /VALUE
### Domain User Info ###
wmic /NAMESPACE:\\root\directory\ldap PATH ds_user where "ds_samaccountname='testAccount'" GET 
### List All Users ###
wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname
### List All Groups ###
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group GET ds_samaccountname
### Members of A Group ###
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group where "ds_samaccountname='Domain Admins'" Get ds_member /Value
wmic path win32_groupuser where (groupcomponent="win32_group.name="domain admins",domain="YOURDOMAINHERE"")
### List All Computers ###
wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_samaccountname
wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_dnshostname
### Execute Remote Command ###
wmic process call create "cmd.exe /c calc.exe"
### Enable Remote Desktop ###
#wmic rdtoggle where AllowTSConnections="0" call SetAllowTSConnections "1"
#wmic /node:remotehost path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"


#>

