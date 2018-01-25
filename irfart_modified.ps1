#========================================================================================================================================
#By voilàviola, 01/2018
#Modified from irFARTpull master branch
#Add: collect data from localhost
#Add: collect usrclass.dat, jumplists, powershell command history
#Syntax Modifications for parsing parameters correctly in powershell
#Test environment: Powershell v5, localhost win10, dist host win7
#========================================================================================================================================

<#  
.SYNOPSIS  
    IR Forensic ARTifact pull (irFArtpull)

.DESCRIPTION
irFARTpull is a PowerShell script utilized to pull several forensic artifacts from a live Win7+ system on your network. It DOES NOT utilize WinRM remote capabilities.

Artifacts it grabs:
	- Disk Information
	- System Information
	- User Information
	- Network Configuration
	- Netstat info
	- Route Table, ARP Table, DNS Cache, HOSTS file
	- Running Processes
	- Services
	- Event Logs (System, Security, Application, Windows Powershell)
	- Prefetch Files
	###############- CCM_RecentlyUsedApps
	- MFT
	- USNJournal
	- NTFS LogFile
	- Registry Files
	- Shellbag: NTUSER.dat and UsrClass.dat
	- Jumplists
	- Internet History Files (IE, Firefox, Chrome)
	
When done collecting the artifacts, it will 7zip the data and pull the info off the box for offline analysis. 

.PARAMETER target
    This is the target IP of the computer where you will be collecting artifacts from. Can be IP or Hostname.

.PARAMETER toolsDir
	This the file path location of the tools on the analysis system.

.PARAMETER dumpDir
	This is the file path location you want the artifact collection dumped. (On analysis system or other location like UNC path to server share)

.PARAMETER 7zpass
	This is the password for the compressed & password protected file that the artifacts will be put into.  If entering in one string using -7zpass, you must enclose in quotes like: "password". 

.PARAMETER InetHist
	Answer [Y or Yes] if you want to collect users internet history, or answer [N or No] to not collect users internet history.

.PARAMETER SendMail
	Answer [Y or Yes] if you want an email sent telling the capture is complete, or answer [N or No] to not get one. 

.EXAMPLE
	In this example we are using a HOSTNAME as the target.
	irfartpull.ps1 -target HOSTNAME -toolsdir c:\SOMEPATH\SOMEDIR -dumpdir c:\SOMEPATH\SOMEDIR -7zpass"bob" -inethist N -mail N
.EXAMPLE   ####This example does not work!!!!!!!!!!!! use only .\irfartpull.ps1 and enter manually parameters!!!!
	In this example we are using an IPADDRESS as the target.
	irfartpull.ps1 -target 111.222.333.444 -toolsdir c:\SOMEPATH\SOMEDIR -dumpdir c:\SOMEPATH\SOMEDIR -7zpass"PASSWORD" -inethist N -mail N

.NOTES  
    All testing done on PowerShell v4+
	
	Requires:
		RawCopy.exe,RawCopy64.exe for the extraction of MFT$ and NTUSER.DAT files.
		Requires ExtractUsnJrnl.exe for the extraction of the $USNJ
		Requires Autorunsc.exe for the extraction of auto run info
		Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
	Must be ran as a user that will have Admin creds on the remote system.
	
	The system can be on a domain or standalone, you will have the option to provide credentials that are Domain or Host.
	
.LINK
	
	irFARTpull main -- https://github.com/n3l5/irFARTpull
	
	[REQUIRED TOOLS]
		Rawcopy -- https://github.com/jschicht/RawCopy
		ExtractUsnJrnl -- https://github.com/jschicht/ExtractUsnJrnl
		Autorunsc -- Command line version of Autoruns - https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx
		7-Zip -- Part of the 7-Zip archiver, 7za can be downloaded from here: http://www.7-zip.org/
		
	[VARIOUS ANALYSIS TOOLS]
		RegRipper -- Tool for extracting data from Registry and NTUSER.dat files. https://github.com/keydet89/RegRipper2.8
		WinPrefetchView -- utility to read Prefetch files. http://www.nirsoft.net/utils/win_prefetch_view.html
		MFTDump -- tool to dump the contents of the $MFT. http://malware-hunters.net/2012/09/
		Triforce ANJP -- tool to examining the MFT, LogFile, and USN. https://www.gettriforce.com/product/anjp-free/

#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True,Position=0)]
   [string]$target,
   
   [Parameter(Mandatory=$True,Position=1)]
   [ValidateScript({Test-Path $_ -PathType 'Container'})]
   [string]$toolsDir,
   
   [Parameter(Mandatory=$True,Position=2)]
   [ValidateScript({Test-Path $_ -PathType 'Container'})]
   [string]$dumpDir,
   
   [Parameter(Mandatory=$True,Position=3)]
   [string]$7zpass,    
   
   [Parameter(Mandatory=$True,Position=4)]
   [ValidateSet("Yes","Y","No","N")]
   [string]$InetHist,

   [Parameter(Mandatory=$True,Position=5)]
   [ValidateSet("Yes","Y","No","N")]
   [string]$SendMail
   )

$date = Get-Date -format yyyy-MM-dd_HHmm_
$transcriptLog = $dumpDir + "\$date" + "_irFartpull_Transcript.log"
Start-Transcript $transcriptLog 
echo "=============================================="
echo "=============================================="
Write-Host -Fore Yellow "

  _      ______           _               _ _ 
 (_)    |  ____/\        | |             | | |
  _ _ __| |__ /  \   _ __| |_ _ __  _   _| | |
 | | '__|  __/ /\ \ | '__| __| '_ \| | | | | |
 | | |  | | / ____ \| |  | |_| |_) | |_| | | |
 |_|_|  |_|/_/    \_\_|   \__| .__/ \__,_|_|_|
                             |_|  

" 
echo "=============================================="
Write-Host -Fore Yellow "Run as administrator/elevated privileges!!!"
echo "=============================================="
echo ""

Write-Host -Fore Cyan ">>>>> Press a key to begin...."
[void][System.Console]::ReadKey($TRUE)
echo ""
echo ""
$userDom = Read-Host "Enter your target DOMAIN (if any)..."
$username = Read-Host "Enter you UserID..."
$domCred = "$userDom" + "\$username"
$compCred = "$target" + "\$username"

##Fill credentials based on whether domain or remote system credentials used 

	if (!($userDom)){
		$cred = Get-Credential $compCred
		}
	else {
		$cred = Get-Credential $domCred
		}
	echo ""

#Test if the box is up and running

	Write-Host -Fore Yellow ">>>>> Testing connection to $target...."
	echo ""

#Test Ping & Test Raw Socket (port 445)
	$socket = New-Object net.sockets.tcpclient("$target",445)

	if ((!(Test-Connection -Cn $target -Count 3 -ea 0 -quiet)) -OR (!($socket))) {
			Write-Host -Foreground Magenta "$target appears to be down, network tests failed. See Transcript log at $transcriptLog"
			Stop-Transcript
			}

#Test the share access to remote system, utilizing PSDrive mapping to remote drive
	if (!(New-PSDrive -Name x -PSProvider filesystem -Root \\$target\c$ -Credential $cred)){
			Write-Host -Foreground Magenta "Admin share access to $target likely denied, or the network failed. See Transcript log at $transcriptLog"
			Stop-Transcript
			}

################
##Target is up, start the collection
################

	else {
		Write-Host -Foreground Magenta "  -$target is up, starting the collection-"
	echo ""

#Determine if InetHist is wanted
	if ($InetHist -like "N*") {
		Write-Host -Foregroundcolor Cyan "  -Internet History collection off-"
		}
	echo ""

#Determine if Mail Alert is wanted ask for particulars
	if ($SendMail -like "Y*") {
		$mailTo = Read-Host "Enter alert TO: email address...multiples should separated like such - "user1@abc.com", "user2@abc.com""
		$mailFrom = Read-Host "Enter alert FROM: email address..."
		$smtpServer = Read-Host "Enter SMTP relay server..."
		}
	elseif ((!($SendMail)) -OR ($mail -like "N*")) {
		Write-Host -Foregroundcolor Cyan "  -Mail notification off-"
		}

#Set up DCOM connection (no remote WSMan)
	$dcom = New-CimsessionOption -Protocol DCOM

#Set up Cimsession on $target via DCOM
	$ir = new-cimsession -ComputerName $target -Credential $cred -SessionOption $dcom

#Get system info
	$targetName = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % Name
	$targetIP = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Cimsession $ir | select * | Where {$_.IPenabled -eq "true"} | Where {$_.IPAddress} | Select -ExpandProperty IPAddress | Where{$_ -notlike "*:*"}
	$domain = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % Domain
	$OSname = Get-CimInstance -ClassName Win32_OperatingSystem -Cimsession $ir | % Caption
	$mem = Get-CimInstance -ClassName Win32_PhysicalMemory -Cimsession $ir | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)}
	$mfg = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % Manufacturer
	$model = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % Model
	$type = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % pcsystemtype
	$pctype = Switch ($type){	
		0 {"Unknown system type"}
		1 {"Desktop"}
    	2 {"Mobile/Laptop"}
		3 {"Workstation"}
		4 {"Enterprise Server"}
		5 {"Small Office and Home Office (SOHO) Server"}
		6 {"Appliance PC"}
		7 {"Performance Server"}
		8 {"Maximum"}
		default {"Unknown system type"}
	   }	
	$sernum = Get-CimInstance -ClassName Win32_Bios -Cimsession $ir | % SerialNumber
	$tmzn = Get-CimInstance -ClassName Win32_TimeZone -Cimsession $ir | % Caption
	$currUser = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % Username
	$arch = Get-CimInstance -ClassName Win32_OperatingSystem -Cimsession $ir | % OSArchitecture
	$OSvers = Get-CimInstance -ClassName Win32_OperatingSystem -Cimsession $ir | % version
	$osinstall = Get-CimInstance -ClassName Win32_OperatingSystem -Cimsession $ir | % installdate	
		
	echo ""
	echo "=============================================="
	Write-Host -ForegroundColor Magenta "==[ $targetName - $targetIP"
	Write-Host -ForegroundColor Magenta "==[ Host OS: $OSname $arch"
	Write-Host -ForegroundColor Magenta "==[ Domain: $domain"
	Write-Host -ForegroundColor Magenta "==[ Total memory size: $mem GB"
	Write-Host -ForegroundColor Magenta "==[ Manufacturer: $mfg"
	Write-Host -ForegroundColor Magenta "==[ Model: $model"
	Write-Host -ForegroundColor Magenta "==[ System Type: $pctype"
	Write-Host -ForegroundColor Magenta "==[ Serial Number: $sernum"
	Write-Host -ForegroundColor Magenta "==[ Timezone: $tmzn"
	Write-Host -ForegroundColor Magenta "==[ OS InstallDate: $osinstall"
	Write-Host -ForegroundColor Magenta "==[ Current logged on user: $currUser"
	echo "=============================================="
	echo ""

################
##Set up environment on remote system. IR folder for tools and art folder for artifacts.##
################
##For consistency, the working directory will be located in the "c:\windows\temp\IR" folder on both the target and initiator system.
##Tools will stored directly in the "IR" folder for use. Artifacts collected on the local environment of the remote system will be dropped in the workingdir.

##Set up PSDrive mapping to remote drive
	New-PSDrive -Name x -PSProvider filesystem -Root \\$target\c$ -Credential $cred | Out-Null

	$irFolder = "c:\Windows\Temp\IR"    
	$remoteIRfold = "X:\windows\Temp\IR"   
	$artFolder = $date + $targetName
	$workingDir = $irFolder + "\$artFolder"
	$localDirlist = ("$dumpDir\$artFolder")
	$dirList = ("$remoteIRfold\$artFolder\raw_files","$remoteIRfold\$artFolder\raw_files\logs","$remoteIRfold\$artFolder\network","$remoteIRfold\$artFolder\raw_files\reg","$remoteIRfold\$artFolder\raw_files\disk","$remoteIRfold\$artFolder\raw_files\prefetch")
	$rawFiledir = ("$workingDir\raw_files")
	$diskDir = ("$rawFiledir\disk")
	$sysInfofile = ($localDirlist + "\$targetName" +"_sysinfo.txt")
	
	New-Item -Path $localdirList -ItemType Directory | Out-Null
	New-Item -Path $dirList -ItemType Directory | Out-Null
	
	"==[ $targetName - $targetIP","==[ Host OS: $OSname $arch","==[ Domain: $domain","==[ Total memory size: $mem GB","==[ Manufacturer: $mfg","==[ Model: $model","==[ System Type: $pctype","==[ Serial Number: $sernum","==[ Timezone: $tmzn","==[ OS InstallDate: $osinstall","==[ Current logged on user: $currUser" | out-file $sysInfofile -width 4096 

##connect and move software to target client
	Write-Host -Fore Green "Copying tools...."
	Copy-Item $toolsDir\*.* $remoteIRfold -recurse

##SystemInformation
	Write-Host -Fore Green "Pulling system information...."
	
	Get-CimInstance -ClassName Win32_DiskDrive -Cimsession $ir | Format-Table -auto @{Label="DeviceID";Expression={$_.DeviceID};Align="Left"},@{Label="S/N";Expression={$_.serialnumber};Align="Left"},@{Label="Partitions";Expression={$_.partitions};Align="Left"},@{Label="Size(GB)";Expression={"{0:N0}" -f ($_.Size / 1GB)};Align="Left"},@{Label="MediaType";Expression={$_.MediaType};Align="Left"},@{Label="Interfacetype";Expression={$_.Interfacetype};Align="Left"},@{Label="Model";Expression={$_.Model};Align="Left"} | Out-File -Append $sysInfofile -width 4096
	Get-CimInstance -ClassName Win32_LogicalDisk -Cimsession $ir | Format-Table -auto @{Label="Drive";Expression={$_.DeviceID};Align="Right"},@{Label="Free(GB)";Expression={"{0:N0}" -f ($_.FreeSpace/1GB)};Align="Right"},@{Label="Size(GB)";Expression={"{0:N0}" -f ($_.Size / 1GB)};Align="Right"},@{Label="% Free";Expression={"{0:P0}" -f ($_.FreeSpace / $_.Size)};Align="Right"},@{Label="FileSystem";Expression={$_.Filesystem};Width=25},@{Label="Volume S/N";Expression={$_.VolumeSerialNumber};Width=25},@{Label="Volume Desc";Expression={$_.Description};Width=25} | Out-File -Append $sysInfofile -width 4096
	Get-CimInstance -ClassName Win32_UserProfile -Cimsession $ir | Format-Table -auto @{Label="LastUseTime";Expression={$_.LastUseTime};Align="Left"},@{Label="Localpath";Expression={$_.Localpath};Align="Left"},@{Label="SID";Expression={$_.SID};Align="Left"},@{Label="Loaded";Expression={$_.Loaded};Align="Left"},@{Label="Refcount";Expression={$_.Refcount};Align="Left"},@{Label="Special";Expression={$_.Special};Align="Left"} | Out-File -Append $sysInfofile -width 4096

##Copy Prefetch files
	
	$sfStatus = Get-CimInstance Win32_Service -CimSession $ir | where {$_.displayname -match 'Superfetch'} | % {$_.state -eq 'Running'}
	$pfPath = Test-Path x:\windows\Prefetch\*.pf
	if (($sfStatus) -OR ($pfPath)) {
	Write-Host -Fore Green "Pulling prefetch files...."	
	Copy-Item x:\windows\prefetch\*.pf $remoteIRfold\$artFolder\raw_files\prefetch -recurse
	}

##gather Process info
	Write-Host -Fore Green "Pulling process info...."

	Get-CimInstance -ClassName Win32_Process -Cimsession $ir | foreach {
	$owner = Invoke-CimMethod -InputObject $PSItem -MethodName GetOwner
	$props = [ordered]@{
	Name = $psitem.name
	Domain = $owner.Domain
	User = $owner.User
	CreateDate = $psitem.CreationDate
	ProcessID = $psitem.processid
	ParentProcessID = $psitem.ParentProcessId
	ExecutablePath = $psitem.ExecutablePath
	CommandLine = $psitem.CommandLine
	}
	New-Object -TypeName PSobject -Property $props | Export-CSV $dumpDir\$artFolder\procs.csv -NoTypeInformation -Append
	}

##gather Services info
	Write-Host -Fore Green "Pulling service info...."
	Get-CimInstance -ClassName Win32_Service -Cimsession $ir | select processid,startname,state,name,displayname,pathname,startmode | Export-CSV $dumpDir\$artFolder\services.csv -NoTypeInformation

##Collect CCM_RecentlyUsedApps         ######Does not work in Win10

	If (Get-CimInstance -namespace root\CCM\SoftwareMeteringAgent -Classname CCM_RecentlyUsedApps -Cimsession $ir){
		Get-CimInstance -namespace root\CCM\SoftwareMeteringAgent -Classname CCM_RecentlyUsedApps -Cimsession $ir | select-object explorerfilename,FolderPath,OriginalFileName,LaunchCount,FileSize,LastUsedTime,LastUserName,FileDescription,ProductName,FileVersion,ProductVersion | Export-CSV $dumpDir\$artFolder\CCM_RecentlyUsedApps.csv -NoTypeInformation | Out-Null
		}

##Determine $arch for x86 vs x64 tool use

	if ($arch -match "32"){
		$rawcopy =  "$irFolder\RawCopy.exe"
		}
	elseif ($arch -match "64") {
		$rawcopy =  "$irFolder\RawCopy64.exe"
		}

##gather network  & adapter info
	Write-Host -Fore Green "Pulling network information...."
	Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Cimsession $ir | select * | Where {$_.IPenabled -eq "true" -or $_.DHCPEnabled -eq "true"} | Format-Table -auto @{Label="DNSHostName";Expression={$_.DNSHostName};Align="Left"},@{Label="DNSDomain";Expression={$_.DNSDomain};Align="Left"},@{Label="Description";Expression={$_.Description};Align="Left"},@{Label="DHCPLeaseObtained";Expression={$_.DHCPLeaseObtained};Align="Left"},@{Label="DHCPEnabled";Expression={$_.DHCPEnabled};Align="Left"},@{Label="IPEnabled";Expression={$_.IPEnabled};Align="Left"},@{Label="MACAddress";Expression={$_.MACAddress};Align="Left"},@{l="IPAddress";e={$_.IPAddress -join ","}},@{l="DefaultIPGateway";e={$_.DefaultIPGateway -join ","}},DNSDomain,@{l="DNSServerSearchOrder";e={$_.DNSServerSearchOrder -join ","}} | Out-File -Append $sysInfofile -width 4096
	$netstat = "cmd /c c:\windows\system32\netstat.exe -anob >> c:\netstats.txt"
	$netroute = "cmd /c c:\windows\system32\netstat.exe -r > c:\routetable.txt"
	$dnscache = "cmd /c c:\windows\system32\ipconfig /displaydns > c:\dnscache.txt"
	$arpdata =  "cmd /c c:\windows\system32\arp.exe -a > c:\arpdata.txt"
	if ($target -like "localhost") {   
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netstat | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netroute | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $dnscache | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $arpdata | Out-Null
	} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netstat -ComputerName $target -Credential $cred | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netroute -ComputerName $target -Credential $cred | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $dnscache -ComputerName $target -Credential $cred | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $arpdata -ComputerName $target -Credential $cred | Out-Null
	}
	
	if ($target -like "localhost"){
		$netinfo = @("c:\netstats.txt","c:\routetable.txt","c:\dnscache.txt","c:\arpdata.txt")  
		} else {
		$netinfo = @("x:\netstats.txt","x:\routetable.txt","x:\dnscache.txt","x:\arpdata.txt")
		}
	Copy-Item x:\windows\system32\drivers\etc\hosts $remoteIRfold\$artFolder\network\hosts
	
	do {(Write-Host -ForegroundColor Yellow "   waiting for Network files copy to complete..."),(Start-Sleep -Seconds 5)}  
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'Create'}).ProcessID -eq $null)
	Move-Item -Path $netinfo -Destination $remoteIRfold\$artFolder\network -Force

##Copy Event Log Files
	Write-Host -Fore Green "Pulling event logs...."
	$logLoc = "x:\windows\system32\Winevt\Logs"
	$loglist = @("$logLoc\application.evtx","$logLoc\security.evtx","$logLoc\system.evtx","$logLoc\Windows Powershell.evtx")
	$logDir = $remoteIRfold + $rawFiledir + "\logs"
	Copy-Item -Path $loglist -Destination $remoteIRfold\$artFolder\raw_files\logs\ -Force

##Copy NTFS $LogFile

	Write-Host -Fore Green "Pulling the NTFS Logfile...."
	if ($target -like "localhost"){
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:c:2 /OutputPath:$diskDir" | Out-Null
		} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:c:2 /OutputPath:$diskDir" -ComputerName $target -Credential $cred | Out-Null
		}
		
	do {(Write-Host -ForegroundColor Yellow "   waiting for LogFile copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'rawcopy'}).ProcessID -eq $null)
		
	Write-Host "  [done]"

##Extract USN Journal
	
	Write-Host -Fore Green "Pulling the UsnJrnl...."
	if ($target -like "localhost"){
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\ExtractUsnJrnl.exe c: $diskDir" | Out-Null
		} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\ExtractUsnJrnl.exe c: $diskDir" -ComputerName $target -Credential $cred | Out-Null
		}
		
	do {(Write-Host -ForegroundColor Yellow "   waiting for UsnJrnl copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -eq "ExtractUsnJrnl.exe"}).ProcessID -eq $null)
	
	Write-Host "  [done]"
	
##Copy Reg files
	
	Write-Host -Fore Green "Pulling registry files...."
	
	$regLoc = "c:\windows\system32\config"
	
	if ($target -like "localhost"){
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SOFTWARE /OutputPath:$rawFiledir\reg" | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SYSTEM /OutputPath:$rawFiledir\reg" | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SAM /OutputPath:$rawFiledir\reg" | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SECURITY /OutputPath:$rawFiledir\reg" | Out-Null
		} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SOFTWARE /OutputPath:$rawFiledir\reg" -ComputerName $target -Credential $cred | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SYSTEM /OutputPath:$rawFiledir\reg" -ComputerName $target -Credential $cred | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SAM /OutputPath:$rawFiledir\reg" -ComputerName $target -Credential $cred | Out-Null
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$regLoc\SECURITY /OutputPath:$rawFiledir\reg" -ComputerName $target -Credential $cred | Out-Null
		}
		
	do 	{(Write-Host -ForegroundColor Yellow "   waiting for Reg Files copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'rawcopy'}).ProcessID -eq $null)
			
	Write-Host "  [done]"

##Run AutoRunsc

	Write-Host -Fore Green "Running Autoruns analysis...."
	$autorunArgs = "-a * -h -m -s -t -c * -accepteula > $workingDir\autoruns.csv"
	
	if ($target -like "localhost"){
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c c:\Windows\temp\IR\autorunsc.exe $autorunArgs" | Out-Null
	} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c c:\Windows\temp\IR\autorunsc.exe $autorunArgs" -ComputerName $target -Credential $cred | Out-Null
	}
	
	do {(Write-Host -ForegroundColor Yellow "   waiting for Autoruns to complete..."),(Start-Sleep -Seconds 15)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'autorunsc'}).ProcessID -eq $null)
	
	Write-Host "  [done]"

##Copy Amcache.hve

	if ($OSname -match "Windows 8|Windows 10|Server 2012"){
		$Amcache = "c:\windows\appcompat\programs\amcache.hve"
		if(Test-Path $Amcache){
			Write-Host -Fore Green "Pulling registry files...."
			if ($target -like "localhost"){
				InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$amcache /OutputPath:$rawFiledir" | Out-Null
			} else {
				InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$amcache /OutputPath:$rawFiledir" -ComputerName $target -Credential $cred | Out-Null
			}
			
			do {(Write-Host -ForegroundColor Yellow "   waiting for Amcache copy to complete..."),(Start-Sleep -Seconds 5)}
			until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'rawcopy'}).ProcessID -eq $null)
			
			Write-Host "  [done]"
			}
	}

##Copy Symantec Quarantine Files (default location)##
	$symQ = "x:\ProgramData\Symantec\Symantec Endpoint Protection\1*\Data\Quarantine"
	if (Test-Path -Path "$symQ\*.vbn") {
		Write-Host -Fore Green "Pulling Symantec Quarantine files...."
		New-Item -Path $remoteIRfold\$artFolder\SymantecQuarantine -ItemType Directory  | Out-Null
		Copy-Item -Path "$symQ\*" $remoteIRfold\$artFolder\SymantecQuarantine -Force -Recurse
		}
	else
		{
		Write-Host -Fore Red "No Symantec Quarantine files...."
		}

##Copy Symantec Log Files (default location)##
	$symLog = "x:\ProgramData\Symantec\Symantec Endpoint Protection\1*\Data\Logs"
	if (Test-Path -Path "$symLog\*.log") {
		Write-Host -Fore Green "Pulling Symantec Log files...."
		New-Item -Path $remoteIRfold\$artFolder\SymantecLogs -ItemType Directory  | Out-Null
		Copy-Item -Path "$symLog\*.Log" $remoteIRfold\$artFolder\SymantecLogs -Force -Recurse
		}
	else
		{
		Write-Host -Fore Red "No Symantec Log files...."
		}

##Copy McAfee Quarantine Files (default location)##
	$mcafQ = "x:\Quarantine"
	if (Test-Path -Path "$mcafQ\*.bup") {
		Write-Host -Fore Green "Pulling McAfee Quarantine files...."
		New-Item -Path $remoteIRfold\$artFolder\McAfeeQuarantine -ItemType Directory  | Out-Null
		Copy-Item -Path "$mcafQ\*.bup" $remoteIRfold\$artFolder\McAfeeQuarantine -Force -Recurse
	}
	else
		{
		Write-Host -Fore Red "No McAfee Quarantine files...."
		}

##Copy McAfee Log Files (default location)##
	$mcafLog = "c:\ProgramData\McAfee\DesktopProtection"
	if (Test-Path -Path "$mcafLog\*.txt") {
		Write-Host -Fore Green "Pulling McAfee Log files...."
		New-Item -Path $remoteIRfold\$artFolder\McAfeeAVLogs -ItemType Directory  | Out-Null
		Copy-Item -Path "$mcafLog\*.txt" $remoteIRfold\$artFolder\McAfeeAVLogs -Force -Recurse
	}
	else
		{
		Write-Host -Fore Red "No McAfee Log files...."
		}

###################
##Perform Operations on user files
###################
	echo ""
	echo "=============================================="
	Write-Host -Fore Magenta ">>>[Pulling user profile items]<<<"
	echo "=============================================="


##Determine User Profiles
	if ($OSname -match "Windows 7|Windows 8|Windows 10"){
			$Userpath = "x:\users"
			$localprofiles = Get-CimInstance -ClassName Win32_UserProfile -Cimsession $ir -filter "Special != 'true'" | select * | Where {$_.LastUseTime -gt (get-date).AddDays(-15)}
			foreach ($localprofile in $localprofiles){
				$temppath = $localprofile.localpath
				$source = $temppath + "\ntuser.dat"
				$usrclasssource = $temppath + "\AppData\Local\Microsoft\Windows\UsrClass.dat"  
				$jumplistsource = @(
					$temppath + "\AppData\Roaming\Microsoft\Windows\Recent"   
					$temppath + "\AppData\Roaming\Microsoft\Windows\PowerShell"  
				)
				$eof = $temppath.Length
				$last = $temppath.LastIndexOf('\')
				$count = $eof - $last
				$user = $temppath.Substring($last,$count)
				$destination = "$workingDir\users" + $user
				Write-Host -ForegroundColor Magenta "Pulling items for >> [ $user ]"
				Write-Host -Fore Green "  Pulling Shellbag files for $user...."
				New-Item -Path $remoteIRfold\$artFolder\users\$user -ItemType Directory  | Out-Null
				New-Item -Path $destination\Jumplist -ItemType Directory  | Out-Null   #Add !!!!!!!!
				if ($target -like "localhost"){
					InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$source /OutputPath:$destination" | Out-Null
					InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$usrclasssource /OutputPath:$destination" | Out-Null
				} else {
					InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$source /OutputPath:$destination" -ComputerName $target -Credential $cred | Out-Null
					InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:$usrclasssource /OutputPath:$destination"  -ComputerName $target -Credential $cred | Out-Null
				}
				
				
				Write-Host -Fore Green "  Pulling Jumplist files for $user...."
				
				foreach ($src in $jumplistsource) {
					if (Test-Path $src){
						#if (Test-Path $src -pathType container){
						$jumplistitem = Get-ChildItem -Path $src -ReCurse -Force | foreach {$_.Fullname}
						
						foreach ($ijump in $jumplistitem) {
							Copy-Item -Path $ijump -Destination $destination\Jumplist -Force -Recurse
						}
					}
				}
							
if ($InetHist -like "Y*"){
## Copy Win7 INET files
		$inetexp = "$Userpath\$user\AppData\Local\Microsoft\Windows\History\"
		Write-Host -Fore Green "  Pulling Internet Explorer History files for $user...."
		New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\IE -ItemType Directory | Out-Null
		
		$inethistitem = Get-ChildItem -Path $inetexp -ReCurse -Force | foreach {$_.Fullname}  # PS seem to be non-case sensitive. changed inethist to inethistitem
		foreach ($inet in $inethistitem) {
			Copy-Item -Path $inet -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\IE -Force -Recurse
			}

##Copy FireFox History files##
		$foxpath = "$Userpath\$user\AppData\Roaming\Mozilla\Firefox\profiles"
		
		if (Test-Path -Path $foxpath -PathType Container) {
			Write-Host -Fore Green "  Pulling FireFox Internet History files for $user...."
			New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox -ItemType Directory  | Out-Null
			$ffinet = Get-ChildItem $foxpath -Filter "places.sqlite" -Force -Recurse | Where {($_.LastWriteTime -gt ((get-date).AddDays(-15)))} | % fullname
			Foreach ($ffi in $ffinet) {
				Copy-Item -Path $ffi -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox
				$ffdown = Get-ChildItem $foxpath -Filter "downloads.sqlite" -Force -Recurse | foreach {$_.Fullname}
				}
			Foreach ($ffd in $ffdown) {
				Copy-Item -Path $ffd -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox
				}
			}
		else {
		 	Write-Host -Fore Red "  No FireFox Internet History files for $user...."
	 	 	}

##Copy Chrome History files##
		$chromepath = "$Userpath\$user\AppData\Local\Google\Chrome\User Data\Default"
		
		if (Test-Path -Path $chromepath -PathType Container) {
		#if ($OSvers -like "6*" -and (Test-Path -Path $chromepath -PathType Container)) { 
			Write-Host -Fore Green "  Pulling Chrome Internet History files for $user...."
			New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\Chrome -ItemType Directory  | Out-Null
			$chromeInet = Get-ChildItem $chromepath -Filter "History" -Force -Recurse | Where {($_.LastWriteTime -gt ((get-date).AddDays(-15)))} | % fullname
			Foreach ($chrmi in $chromeInet) {
			Copy-Item -Path $chrmi -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Chrome
				}
			}
		else {
		 Write-Host -Fore Red "  No Chrome Internet History files $user...."
		 	}
		}
	}			
}		
	echo ""	

##Copy $MFT
	Write-Host -Fore Green "Pulling the MFT...."
	
	if ($target -like "localhost"){
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:c:0 /OutputPath:$diskDir" | Out-Null
		} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$rawcopy /FileNamePath:c:0 /OutputPath:$diskDir" -ComputerName $target -Credential $cred | Out-Null
		}
		
	do {(Write-Host -ForegroundColor Yellow "   waiting for MFT copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'rawcopy'}).ProcessID -eq $null)
		
	Write-Host "  [done]"

##Check for lingering processes then move on
	Write-Host -Fore Magenta ">>>[Tactical pause]<<<"
	do {(Write-Host -ForegroundColor Yellow "    Please wait...pausing for previous collection processes to complete..."),(Start-Sleep -Seconds 10)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -match 'rawcopy|ExtractUsnJrnl'}).ProcessID -eq $null)
	Write-Host -ForegroundColor Green "  [done]"

###################
##Package up the data and pull
###################
	echo ""
	echo "=============================================="
	Write-Host -Fore Magenta ">>>[Packaging the collection]<<<"
	echo "=============================================="
	echo ""

##7zip the artifact collection##
	$7z = "cmd /c c:\Windows\temp\IR\7za.exe a $workingDir.7z -p$7zpass -mmt -mhe $workingDir\*" 
	if ($target -like "localhost"){
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z | Out-Null
	} else {
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target -Credential $cred | Out-Null
	}
	do {(Write-Host -ForegroundColor Yellow "   Please wait...packing the collected artifacts..."),(Start-Sleep -Seconds 10)}
	until ((Get-CimInstance -ClassName Win32_Process -Cimsession $ir | select * | where {$_.name -eq '7za.exe'}).ProcessID -eq $null)
	Write-Host -ForegroundColor Yellow "  [Packing complete]"

##size it up
	echo ""
	$name = gci $remoteIRfold\$artfolder'.7z' | % {$_.fullName} 
	Write-Host -ForegroundColor Cyan "[Package Stats]"
	$dirsize = "{0:N2}" -f ((Get-ChildItem $remoteIRfold\$artFolder -recurse | Measure-Object -property length -sum ).Sum / 1MB) + " MB"
	Write-Host -ForegroundColor Cyan "  Working Dir: $dirsize "
	$7zsize = "{0:N2}" -f ((Get-ChildItem $remoteIRfold\$artfolder'.7z' | Measure-Object -property length -sum ).Sum / 1MB) + " MB" 
	Write-Host -ForegroundColor Cyan "  $name size: $7zsize "
	echo ""
	Write-Host -Fore Green "Transfering the package...."
	if (!(Test-Path -Path $irFolder -PathType Container)){
		New-Item -Path $irFolder -ItemType Directory  | Out-Null
	}

	Move-Item $remoteIRfold\$artfolder'.7z' $dumpDir\$artFolder  
	Write-Host -Fore Yellow "  [done]"
	echo ""

##Delete the IR folder##
	Write-Host -Fore Green "Removing the working environment...."
	Remove-Item $remoteIRfold -Recurse -Force  
	if ($target -notlike "localhost"){
		Remove-Item $irFolder -Recurse -Force
	}
	echo ""

##Remove CimSession
	Get-CimSession | Remove-CimSession

##Disconnect the PSDrive X mapping##
	Remove-PSDrive X

#Display the package name

	Write-Host -Fore Cyan "Artifact package name: [  $name  ]"
	echo ""

#Alert script is done if requested
	if ($mail -like "Y*") {
	$body = @"
	$username - initiated Incident Response artifact pull
	Incident Name: $artFolder
	IRFartpull package size: $7zsize
"@
Send-MailMessage -To "$mailTo" -Subject "IRFartpull done" -Body $body -From $mailFrom -SmtpServer $smtpServer
	}

##Ending
	echo "=============================================="
	Write-Host -ForegroundColor Magenta ">>>>>>>>>>[[ irFArtPull complete ]]<<<<<<<<<<<"
	echo "=============================================="
	Stop-Transcript
	$finalTrans = ($localDirlist + "\$targetname" + "_irFartpull_Transcript.log")
	Move-Item $transcriptLog $finalTrans
	}
