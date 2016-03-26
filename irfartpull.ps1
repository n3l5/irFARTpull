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
	- Event Logs (System, Security, Application)
	- Prefetch Files
	- MFT$
	- NTFS LogFile
	- Registry Files
	- User NTUSER.dat files
	- Java IDX files
	- Internet History Files (IE, Firefox, Chrome)
	
When done collecting the artifacts, it will 7zip the data and pull the info off the box for offline analysis. 

.PARAMETER Target
    This is the target computer where you will be collecting artifacts from.

.PARAMETER ToolsDir
	This the file path location of the tools on the analysis system.

.PARAMETER DumpDir
	This is the file path location you want the artifact collection dumped. (On analysis system or other location like UNC path to server share)

.PARAMETER 7zpass
	This is the password for the compressed & password protected file that the artifacts will be put into.

.PARAMETER mail
	Answer [Y] Yes if you want an email sent telling the capture is complete, or answer [N] No to not get one. 

.NOTEs:  
    
	All testing done on PowerShell v4
	Requires Remote Registry PowerShell Module for collecting XP remote registy entries
	Requires RawCopy64.exe for the extraction of MFT$ and NTUSER.DAT files.
	Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
	Assumed Directories:
	c:\tools\resp\ - where the RawCopy64.exe, Autorunsc.exe, and 7za.exe exist
	c:\windows\temp\IR - Where the work will be done/copied
		
	Must be ran as a user that will have Admin creds on the remote system. The assumption is that the target system is part of a domain.
	
    LINKs:  
	
	irFARTpull main - https://github.com/n3l5/irFARTpull
	
	Links to required tools:
	mft2csv - Part of the mft2csv suite, RawCopy can be downloaded here: https://code.google.com/p/mft2csv/
	Autorunsc - Command line version of Autoruns; shows the programs configure to run during login, system bootup, and application startup plug-ins.
	7-Zip - Part of the 7-Zip archiver, 7za can be downloaded from here: http://www.7-zip.org/
		
	Various tools for analysis of the artifacts:
	RegRipper - Tool for extracting data from Registry and NTUSER.dat files. https://code.google.com/p/regripper/
	WinPrefetchView - utility to read Prefetch files. http://www.nirsoft.net/utils/win_prefetch_view.html
	MFTDump - tool to dump the contents of the $MFT. http://malware-hunters.net/2012/09/
	Triforce ANJP - tool to examining the MFT, LogFile, and USN.

#>
Param(
  [Parameter(Mandatory=$True,Position=0)]
   [string]$target,
   
   [Parameter(Mandatory=$True)]
   [string]$toolsDir,
   
   [Parameter(Mandatory=$True)]
   [string]$dumpDir,
   
   [Parameter(Mandatory=$True)]
   [string]$7zpass,
   
   [Parameter(Mandatory=$True)]
   [string]$mail
   )
   
echo "=============================================="
echo "=============================================="
Write-Host -Fore Magenta "

  _      ______           _               _ _ 
 (_)    |  ____/\        | |             | | |
  _ _ __| |__ /  \   _ __| |_ _ __  _   _| | |
 | | '__|  __/ /\ \ | '__| __| '_ \| | | | | |
 | | |  | | / ____ \| |  | |_| |_) | |_| | | |
 |_|_|  |_|/_/    \_\_|   \__| .__/ \__,_|_|_|
                             | |              
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
	if ((!(Test-Connection -Cn $target -Count 3 -ea 0 -quiet)) -OR (!($socket = New-Object net.sockets.tcpclient("$target",445)))) {
		Write-Host -Foreground Magenta "$target appears to be down"
		}

################
##Target is up, start the collection
################

else {
Write-Host -Foreground Magenta "  -$target is up, starting the collection-"

#Determine if Mail Alert is wanted ask for particulars
	if ($mail -like "Y*") {
		$mailTo = Read-Host "Enter alert TO: email address...multiples should separated like such - "user1@abc.com", "user2@abc.com""
		$mailFrom = Read-Host "Enter alert FROM: email address..."
		$smtpServer = Read-Host "Enter SMTP relay server..."
		}
elseif ((!($mail)) -OR ($mail -like "N*")) {
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
	$pctype = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % pcsystemtype
	$sernum = Get-CimInstance -ClassName Win32_Bios -Cimsession $ir | % SerialNumber
	$tmzn = Get-CimInstance -ClassName Win32_TimeZone -Cimsession $ir | % Caption
	$currUser = Get-CimInstance -ClassName Win32_ComputerSystem -Cimsession $ir | % Username
	$arch = Get-CimInstance -ClassName Win32_OperatingSystem -Cimsession $ir | % OSArchitecture
	$OSvers = Get-CimInstance -ClassName Win32_OperatingSystem -Cimsession $ir | % version
		
	echo ""
	echo "=============================================="
	Write-Host -ForegroundColor Magenta "==[ $targetName - $targetIP"
	Write-Host -ForegroundColor Magenta "==[ Host OS: $OSname $arch"
	Write-Host -ForegroundColor Magenta "==[ $targetName - $targetIP"
	Write-Host -ForegroundColor Magenta "==[ Domain: $domain"
	Write-Host -ForegroundColor Magenta "==[ Total memory size: $mem GB"
	Write-Host -ForegroundColor Magenta "==[ Manufacturer: $mfg"
	Write-Host -ForegroundColor Magenta "==[ Model: $model"
	Write-Host -ForegroundColor Magenta "==[ System Type: $pctype"
	Write-Host -ForegroundColor Magenta "==[ Serial Number: $sernum"
	Write-Host -ForegroundColor Magenta "==[ Timezone: $tmzn"
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

	$irFolder = "c:\Windows\Temp\IR\"
	$remoteIRfold = "X:\windows\Temp\IR"
	$date = Get-Date -format yyyy-MM-dd_HHmm_
	$artFolder = $date + $targetName
	$workingDir = $irFolder + "\$artFolder"
	$dirList = ("$remoteIRfold\$artFolder\logs","$remoteIRfold\$artFolder\network","$remoteIRfold\$artFolder\prefetch","$remoteIRfold\$artFolder\reg")
	New-Item -Path $dirList -ItemType Directory | Out-Null
	
	"==[ $targetName - $targetIP","==[ Host OS: $OSname $arch","==[ Domain: $domain","==[ Total memory size: $mem GB","==[ Manufacturer: $mfg","==[ Model: $model","==[ System Type: $pctype","==[ Serial Number: $sernum","==[ Timezone: $tmzn","==[ Current logged on user: $currUser" | out-file $remoteIRfold\$targetName_sysinfo.txt

##connect and move software to target client
	Write-Host -Fore Green "Copying tools...."
	Copy-Item $toolsDir\*.* $remoteIRfold -recurse

##SystemInformation
	Write-Host -Fore Green "Pulling system information...."
	
	Get-CimInstance -ClassName Win32_DiskDrive -Cimsession $ir | Format-Table -auto @{Label="DeviceID";Expression={$_.DeviceID};Align="Left"},@{Label="S/N";Expression={$_.serialnumber};Align="Left"},@{Label="Partitions";Expression={$_.partitions};Align="Left"},@{Label="Size(GB)";Expression={"{0:N0}" -f ($_.Size / 1GB)};Align="Left"},@{Label="MediaType";Expression={$_.MediaType};Align="Left"},@{Label="Interfacetype";Expression={$_.Interfacetype};Align="Left"},@{Label="Model";Expression={$_.Model};Align="Left"} | Out-File -Append $remoteIRfold\$targetName_sysinfo.txt
	Get-CimInstance -ClassName Win32_LogicalDisk -Cimsession $ir | Format-Table -auto @{Label="Drive";Expression={$_.DeviceID};Align="Right"},@{Label="Free(GB)";Expression={"{0:N0}" -f ($_.FreeSpace/1GB)};Align="Right"},@{Label="Size(GB)";Expression={"{0:N0}" -f ($_.Size / 1GB)};Align="Right"},@{Label="% Free";Expression={"{0:P0}" -f ($_.FreeSpace / $_.Size)};Align="Right"},@{Label="FileSystem";Expression={$_.Filesystem};Width=25},@{Label="Volume S/N";Expression={$_.VolumeSerialNumber};Width=25},@{Label="Volume Desc";Expression={$_.Description};Width=25} | Out-File -Append $remoteIRfold\$targetName_sysinfo.txt
	Get-CimInstance -ClassName Win32_UserProfile  -Cimsession $ir | Format-Table -auto @{Label="LastUseTime";Expression={$_.LastUseTime};Align="Left"},@{Label="Localpath";Expression={$_.Localpath};Align="Left"},@{Label="SID";Expression={$_.SID};Align="Left"},@{Label="Loaded";Expression={$_.Loaded};Align="Left"},@{Label="Refcount";Expression={$_.Refcount};Align="Left"},@{Label="Special";Expression={$_.Special};Align="Left"} | Out-File -Append $remoteIRfold\$targetName_sysinfo.txt

##gather network  & adapter info
	Write-Host -Fore Green "Pulling network information...."
	Get-WMIObject Win32_NetworkAdapterConfiguration -ComputerName $target -Filter "IPEnabled='TRUE'" -Credential $cred | select DNSHostName,ServiceName,MacAddress,@{l="IPAddress";e={$_.IPAddress -join ","}},@{l="DefaultIPGateway";e={$_.DefaultIPGateway -join ","}},DNSDomain,@{l="DNSServerSearchOrder";e={$_.DNSServerSearchOrder -join ","}},Description | Export-CSV $remoteIRfold\$artFolder\network\netinfo.csv -NoTypeInformation | Out-Null

	$netstat = "cmd /c c:\windows\system32\netstat.exe -anob >> c:\netstats.txt"
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netstat -ComputerName $target -Credential $cred | Out-Null

	$netroute = "cmd /c c:\windows\system32\netstat.exe -r > c:\routetable.txt"
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netroute -ComputerName $target -Credential $cred | Out-Null

	$dnscache = "cmd /c c:\windows\system32\ipconfig /displaydns > c:\dnscache.txt"
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $dnscache -ComputerName $target -Credential $cred | Out-Null

	$arpdata =  "cmd /c c:\windows\system32\arp.exe -a > c:\arpdata.txt"
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $arpdata -ComputerName $target -Credential $cred | Out-Null

	$netinfo = @("x:\netstats.txt","x:\routetable.txt","x:\dnscache.txt","x:\arpdata.txt")
	Copy-Item x:\windows\system32\drivers\etc\hosts $remoteIRfold\$artFolder\network\hosts

##gather Process info
	Write-Host -Fore Green "Pulling process info...."
	Get-WMIObject Win32_Process -Computername $target -Credential $cred | select-object CreationDate,ProcessName,parentprocessid,processid,@{n='Owner';e={$_.GetOwner().User}},ExecutablePath,commandline| Export-CSV $remoteIRfold\$artFolder\procs.csv -NoTypeInformation | Out-Null

	#$procfilepath = (Get-WMIObject Win32_Process -ComputerName $target).executablepath
	#foreach ($procfile in $procFilePath){
	#		$convertpath = $procfile -replace "c:", "\\$target\c$"
	#		dir $convertpath | where-object {!$_.psiscontainer } | get-Filehash -algo md5 | select hash,path | Export-Csv -NoTypeInformation -Append $remoteIRfold\$artFolder\process-hashes.csv | Out-Null
	#		}
		
##gather Services info
	Write-Host -Fore Green "Pulling service info...."
	Get-WMIObject Win32_Service -Computername $target -Credential $cred | Select processid,name,state,displayname,pathname,startmode | Export-CSV $remoteIRfold\$artFolder\services.csv -NoTypeInformation | Out-Null

##gather the Java Version
	Get-WmiObject -Class CIM_Datafile -Computername $target -Credential $cred -Filter '(Name="C:\\Program Files\\Java\\jre7\\bin\\java.dll" OR Name="C:\\Program Files (x86)\\Java\\jre7\\bin\\java.dll")' | Select-Object -Property name,version | Out-File $remoteIRfold\$artFolder\java-version.txt

##gather Patch/Hotfix  info
	Get-Hotfix -ComputerName $target -Credential $cred | select-object InstalledOn,Description,HotFixID,Caption,InstalledBy | sort Installedon | Export-CSV $remoteIRfold\$artFolder\hotfixes.csv -NoTypeInformation | Out-Null

##Copy Log Files
	Write-Host -Fore Green "Pulling event logs...."
	$logLoc = "x:\windows\system32\Winevt\Logs"
	$loglist = @("$logLoc\application.evtx","$logLoc\security.evtx","$logLoc\system.evtx")
	Copy-Item -Path $loglist -Destination $remoteIRfold\$artFolder\logs\ -Force

##Run AutoRunsc
	
	Write-Host -Fore Green "Running Autoruns analysis...."
	$autorunArgs = "-a * -h -m -s -t -c * -accepteula > $workingDir\autoruns.csv"
	
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c c:\Windows\temp\IR\autorunsc.exe $autorunArgs" -ComputerName $target -Credential $cred | Out-Null
	
	do {(Write-Host -ForegroundColor Yellow "  waiting for Autoruns to complete..."),(Start-Sleep -Seconds 15)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='autorunsc.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "autorunsc.exe"}).ProcessID -eq $null)
	
	Write-Host "  [done]"


##Copy Prefetch files
	
	Write-Host -Fore Green "Pulling prefetch files...."
	
	Copy-Item x:\windows\prefetch\*.pf $remoteIRfold\$artFolder\prefetch -recurse

##Copy $MFT
	Write-Host -Fore Green "Pulling the MFT...."
	if ($arch -like "32") 
	{
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy.exe c:0 $workingDir" -ComputerName $target -Credential $cred | Out-Null
	}
	if ($arch -like "64") 
	{
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe c:0 $workingDir" -ComputerName $target -Credential $cred | Out-Null
	}
	
	do {(Write-Host -ForegroundColor Yellow "  waiting for MFT copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='RawCopy64.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "RawCopy64.exe"}).ProcessID -eq $null)
	
	Write-Host "  [done]"

##Copy $LogFile

	Write-Host -Fore Green "Pulling the NTFS Logfile...."
	if ($arch -like "32") 
	{
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy.exe c:2 $workingDir" -ComputerName $target -Credential $cred | Out-Null
	}
	if ($arch -like "64") 
	{
		InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe c:2 $workingDir" -ComputerName $target -Credential $cred | Out-Null
	}
	
	do {(Write-Host -ForegroundColor Yellow "  waiting for LogFile copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='RawCopy64.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "RawCopy64.exe"}).ProcessID -eq $null)
	
	Write-Host "  [done]"

##Copy Reg files
	Write-Host -Fore Green "Pulling registry files...."
	
	$regLoc = "c:\windows\system32\config\"

	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe $regLoc\SOFTWARE $workingDir\reg" -ComputerName $target -Credential $cred | Out-Null
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe $regLoc\SYSTEM $workingDir\reg" -ComputerName $target -Credential $cred | Out-Null
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe $regLoc\SAM $workingDir\reg" -ComputerName $target -Credential $cred | Out-Null
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe $regLoc\SECURITY $workingDir\reg" -ComputerName $target -Credential $cred | Out-Null

	do 	{(Write-Host -ForegroundColor Yellow "  waiting for Reg Files copy to complete..."),(Start-Sleep -Seconds 5)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='RawCopy64.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "RawCopy64.exe"}).ProcessID -eq $null)
			
	Write-Host "  [done]"

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
		Move-Item -Path $netinfo -Destination $remoteIRfold\$artFolder\network -Force

###################
##Perform Operations on user files
###################
	echo ""
	echo "=============================================="
	Write-Host -Fore Magenta ">>>[Pulling user profile items]<<<"
	echo "=============================================="


##Determine User Profiles
if ($OSvers -like "6*"){
		$W7path = "x:\users"
		$localprofiles = Get-WMIObject Win32_UserProfile -filter "Special != 'true'" -ComputerName $target -Credential $cred | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15) }
		foreach ($localprofile in $localprofiles){
			$temppath = $localprofile.localpath
			$source = $temppath + "\ntuser.dat"
			$eof = $temppath.Length
			$last = $temppath.LastIndexOf('\')
			$count = $eof - $last
			$user = $temppath.Substring($last,$count)
			$destination = "$workingDir\users" + $user
			Write-Host -ForegroundColor Magenta "Pulling items for >> [ $user ]"
			Write-Host -Fore Green "  Pulling NTUSER.DAT file for $user...."
			New-Item -Path $remoteIRfold\$artFolder\users\$user -ItemType Directory  | Out-Null
			InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "$irFolder\RawCopy64.exe $source $destination" -ComputerName $target -Credential $cred | Out-Null
			#dir $w7path\$user -Recurse | where-object {!$_.psiscontainer } | get-Filehash -algo md5 | select hash,pathdir  | Export-Csv -NoTypeInformation -Append $remoteIRfold\$artFolder\user-hashes.csv
			#gci $w7path\$user -Include *.exe,*.dll,*.zip,*.tmp -Recurse -Force -File -ErrorAction SilentlyContinue | select Name,CreationTime,CreationTimeUtc,@{Name="Size";Expression={"{0:N0}" -f ($_.Length / 1Kb)}},@{Label='Hash'; Expression={(Get-FileHash -Algorithm $hashalgorithm $psitem.fullname).hash}},Fullname | export-csv -Append -NoTypeInformation $remoteIRfold\$artFolder\users\$user\userhashes.csv
			#Write-Host "$hashcount user hashes"

##Pull IDX Files##
		$W7idxpath = "$W7path\$user\AppData\LocalLow\Sun\Java\Deployment\cache\6.0\"
		#gci $W7idxpath -Recurse -Force -File -ErrorAction SilentlyContinue | select Name,CreationTime,CreationTimeUtc,@{Name="Size";Expression={"{0:N0}" -f ($_.Length / 1Kb)}},@{Label='Hash'; Expression={(Get-FileHash -Algorithm $hashalgorithm $psitem.fullname).hash}},Fullname | export-csv -append -NoTypeInformation $remoteIRfold\$artFolder\users\$user\userIDXhashes.csv
		if(Test-Path $W7idxpath -PathType Container) {
			Write-Host -Fore Green "  Pulling IDX files for $user....(W7)"
			$idxFiles = Get-ChildItem -Path $W7idxpath -Filter "*.idx" -Force -Recurse | Where-Object {$_.Length -gt 0 -and $_.LastWriteTime -gt (get-date).AddDays(-15)} | foreach {$_.Fullname}
			Write-Host -Fore Yellow "    pulling IDX files...."
			New-Item -Path $remoteIRfold\$artFolder\users\$user\idx -ItemType Directory  | Out-Null
			foreach ($idx in $idxFiles){
			Copy-Item -Path $idx -Destination $remoteIRfold\$artFolder\users\$user\idx -recurse
				}
		}
		else {
	 	 	Write-Host -Fore Red "  No IDX files newer than 15 days for $user...."
	 	 	}

## Copy Win7 INET files
		$Win7inet = "$W7path\$user\AppData\Local\Microsoft\Windows\History\"
		Write-Host -Fore Green "  Pulling Internet Explorer History files for $user...."
		New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\IE -ItemType Directory | Out-Null
		$inethist = Get-ChildItem -Path $Win7inet -ReCurse -Force | foreach {$_.Fullname}
		foreach ($inet in $inethist) {
			Copy-Item -Path $inet -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\IE -Force -Recurse
			}

##Copy FireFox History files##
		$w7foxpath = "$W7path\$user\AppData\Roaming\Mozilla\Firefox\profiles"
		if (Test-Path -Path $w7foxpath -PathType Container) {
			Write-Host -Fore Green "  Pulling FireFox Internet History files for $user....(W7)"
			New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox -ItemType Directory  | Out-Null
			$ffinet = Get-ChildItem $w7foxpath -Filter "places.sqlite" -Force -Recurse | foreach {$_.Fullname}
			Foreach ($ffi in $ffinet) {
				Copy-Item -Path $ffi -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox
				$ffdown = Get-ChildItem $w7foxpath -Filter "downloads.sqlite" -Force -Recurse | foreach {$_.Fullname}
				}
			Foreach ($ffd in $ffdown) {
				Copy-Item -Path $ffd -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox
				}
			}
		else {
		 	Write-Host -Fore Red "  No FireFox Internet History files for $user...."
	 	 	}

##Copy Chrome History files##
	$W7chromepath = "$W7path\$user\AppData\Local\Google\Chrome\User Data\Default"
		if ($OSvers -like "6*" -and (Test-Path -Path $W7chromepath -PathType Container)) {
			Write-Host -Fore Green "  Pulling Chrome Internet History files for $user....(W7)"
			New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\Chrome -ItemType Directory  | Out-Null
			$chromeInet = Get-ChildItem $W7chromepath -Filter "History" -Force -Recurse | foreach {$_.Fullname}
			Foreach ($chrmi in $chromeInet) {
			Copy-Item -Path $chrmi -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Chrome
				}
			}
		else {
		 Write-Host -Fore Red "  No Chrome Internet History files $user...."
		 	}
			}
		}
	
Get-ChildItem $remoteIRfold -Force -Recurse | Export-CSV $remoteIRfold\$artFolder\FileReport.csv
echo ""
Write-Host -Fore Magenta ">>>[Tactical pause]<<<"
do {(Write-Host -ForegroundColor Yellow "  Please wait...pausing for previous collection processes to complete..."),(Start-Sleep -Seconds 10)}
until ((Get-WMIobject -Class Win32_process -ComputerName $target -Credential $cred | Where-Object {$_.GetOwner().User -eq "$username"}).Count -eq 0)
Write-Host -ForegroundColor Yellow "  [done]"


###################
##Package up the data and pull
###################
echo ""
echo "=============================================="
Write-Host -Fore Magenta ">>>[Packaging the collection]<<<"
echo "=============================================="
echo ""

##7zip the artifact collection##
$7z = "cmd /c c:\Windows\temp\IR\7za.exe a $workingDir.7z -p$7zpass -mmt -mhe $workingDir"
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target -Credential $cred | Out-Null
do {(Write-Host -ForegroundColor Yellow "  packing the collected artifacts..."),(Start-Sleep -Seconds 10)}
until ((Get-WMIobject -Class Win32_process -Filter "Name='7za.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "7za.exe"}).ProcessID -eq $null)
Write-Host -ForegroundColor Yellow "  Packing complete..."

##size it up
echo ""
$name = gci $remoteIRfold\$artfolder.7z | % {$_.fullName}
Write-Host -ForegroundColor Cyan "[Package Stats]"
$dirsize = "{0:N2}" -f ((Get-ChildItem $remoteIRfold\$artFolder -recurse | Measure-Object -property length -sum ).Sum / 1MB) + " MB"
Write-Host -ForegroundColor Cyan "  Working Dir: $dirsize "
$7zsize = "{0:N2}" -f ((Get-ChildItem $remoteIRfold\$artfolder.7z | Measure-Object -property length -sum ).Sum / 1MB) + " MB"
Write-Host -ForegroundColor Cyan "  $name size: $7zsize "
echo ""
Write-Host -Fore Green "Transfering the package...."
if (!(Test-Path -Path $irFolder -PathType Container)){
	New-Item -Path $irFolder -ItemType Directory  | Out-Null
}

Move-Item $remoteIRfold\$artfolder.7z $dumpDir
Write-Host -Fore Yellow "  [done]"
echo ""
###Delete the IR folder##
Write-Host -Fore Green "Removing the working environment...."
Remove-Item $remoteIRfold -Recurse -Force 
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
$date2 = Get-Date -format yyyy-MM-dd_HHmm
$body = @"
$username - initiated Incident Response artifact pull
Incident Name: $artFolder
IRFartpull package size: $7zsize
"@
Send-MailMessage -To "$mailTo" -Subject "IRFartpull done" -Body $body -From $mailFrom -SmtpServer $smtpServer
}

##Ending##
echo "=============================================="
Write-Host -ForegroundColor Magenta ">>>>>>>>>>[[ irFArtPull complete ]]<<<<<<<<<<<"
echo "=============================================="
}