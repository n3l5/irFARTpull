<#  
.SYNOPSIS  
    IR Forensic ARTifact Pull (irFARTPull)
.DESCRIPTION
    blah
	blah
	blah
.NOTES  
    blah
	blah
.LINK  
	none
.EXAMPLE  

 
Description
-----------
blah blah blah    
#>

##Run as administrator/elevated privileges
echo "++++++++++++++++++++++++++++"
echo "++++++++++++++++++++++++++++"
echo "Running irFartpull............."
echo "Run as administrator/elevated privileges!!!"
echo "++++++++++++++++++++++++++++"
echo "++++++++++++++++++++++++++++"
echo "++++++++++++++++++++++++++++"
echo "Press a key....."
[void][System.Console]::ReadKey($TRUE)

$target = read-host "Please enter a hostname or IP..."

$QueryString = ('Select StatusCode From Win32_PingStatus Where Address = "' + $target + '"') 
$ResultsSet = Gwmi -Q "$QueryString" 
 
If ($ResultsSet.StatusCode -Eq 0) 
{
Write-Host -Fore Green "The Device Is On Line"
} 
Else 
{
Write-Host -Fore Red "The Device Is Off Line"
Write-Host "Press any key to exit..."
[void][System.Console]::ReadKey($TRUE)
Break
}

################
##Set up environment on remote system. IR folder for tools and art folder for artifacts.##
##Set up PSDrive mapping to remote drive
New-PSDrive -Name X -PSProvider filesystem -Root \\$target\c$

##For consistentancy, the working directory will be located in the "c:\windows\temp\IR" folder on both the target and initiator sytem.
##Tools will stored directly in the "IR" folder for use. Artifacts collected on the local environment of the remote system will be dropped in the workingdir.

$date = Get-Date -format yyyy-MM-dd_HHmm_
$targetName = Get-WMIObject Win32_ComputerSystem -ComputerName $target | ForEach-Object Name
$irFolder = "windows\temp\IR\"
$artFolder = $date + $targetName
$workingDir = $irFolder + $artFolder
##create local IR directory
New-Item -Path c:\$workingDir -ItemType Directory
##create remote IR\workingdir directories
$dirList = ("x:\$workingDir\idx","x:\$workingDir\logs","x:\$workingDir\network","x:\$workingDir\prefetch","x:\$workingDir\reg","x:\$workingDir\users")
New-Item -Path $dirList -ItemType Directory


##connect and move software to target client
$tools = "c:\tools\resp\*.*"
Copy-Item $tools x:\$irFolder -recurse

##SystemInformation
Get-WMIObject Win32_LogicalDisk -ComputerName $target | Select DeviceID,DriveType,@{l="Drive Size";e={$_.Size / 1GB -join ""}},@{l="Free Space";e={$_.FreeSpace / 1GB -join ""}} | Export-CSV c:\$workingDir\diskInfo.csv -NoTypeInformation
Get-WMIObject Win32_ComputerSystem -ComputerName $target | Select Name,UserName,Domain,Manufacturer,Model,PCSystemType | Export-CSV c:\$workingDir\systemInfo.csv -NoTypeInformation
Get-WmiObject Win32_UserProfile -ComputerName $target | select Localpath,SID,LastUseTime | Export-CSV c:\$workingDir\users.csv -NoTypeInformation

##gather network  & adapter info
Get-WMIObject Win32_NetworkAdapterConfiguration -ComputerName $target -Filter "IPEnabled='TRUE'" | select DNSHostName,ServiceName,MacAddress,@{l="IPAddress";e={$_.IPAddress -join ","}},@{l="DefaultIPGateway";e={$_.DefaultIPGateway -join ","}},DNSDomain,@{l="DNSServerSearchOrder";e={$_.DNSServerSearchOrder -join ","}},Description | Export-CSV $workingDir\netinfo.csv -NoTypeInformation

$netstat = "cmd /c c:\windows\system32\netstat.exe -anob > c:\$workingDir\network\netstats.txt"
$netroute = "cmd /c c:\windows\system32\netstat.exe -r > c:\$workingDir\network\routetable.txt"
$dnscache = "cmd /c c:\windows\system32\ipconfig /displaydns > c:\$workingDir\network\dnscache.txt"
$arpdata =  "cmd /c c:\windows\system32\netstat.exe -r > c:\$workingDir\network\arpdata.txt"

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netstat -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netroute -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $arpdata -ComputerName $target
Get-Content x:\windows\system32\drivers\etc\hosts | Out-File $workingDir\network\hosts.txt 


##gather Process info
Get-WMIObject Win32_Process -Computername $target | select name,parentprocessid,processid,executablepath,commandline | Export-CSV c:\$workingDir\procs.csv -NoTypeInformation

##gather Services info
Get-WMIObject Win32_Service -Computername $target | Select processid,name,state,displayname,pathname,startmode | Export-CSV c:\$workingDir\services.csv -NoTypeInformation

####################
##Copy Artifacts on the Target System
####################
$rawcpy = "cmd /c c:\$irFolder\RawCopy64.exe"


##Copy Log Files
$logLoc = "c:\windows\sysnative\Winevt\Logs"
$loglist = @("$logLoc\application.evtx","$logLoc\security.evtx","$logLoc\system.evtx")
Copy-Item -Path $loglist -Destination $workingDir\logs\ -Force

##Copy Prefetch files
Copy-Item x:\windows\prefetch\*.pf x:\$workingDir\prefetch -recurse

##Copy MFT$
$mftCopy = "cmd /c c:\$irFolder\RawCopy64.exe c:0 $workingDir"
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $mftCopy -ComputerName $target

##Copy Reg files
$regLoc = "c:\windows\system32\config"
$soft = "cmd /c c:\$irFolder\RawCopy64.exe $regLoc\software $workingDir\reg"
$sys = "cmd /c c:\$irFolder\RawCopy64.exe $regLoc\system $workingDir\reg"
$sam = "cmd /c c:\$irFolder\RawCopy64.exe $regLoc\SAM $workingDir\reg"
$sec = "cmd /c c:\$irFolder\RawCopy64.exe $regLoc\sec $workingDir\reg"

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $soft -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $syst -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $sam -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $sec -ComputerName $target


###################
##Perform Operations on user files
###################

##Filter out special accounts profiles....
##Get-WMIObject Win32_UserProfile -filter "Special != 'true'"


##collect the profiles actually used in the last 15 days
$fullProf = @(Get-WMIObject Win32_UserProfile -filter "Special != 'true'" | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15)} | foreach-object {$_.localpath})


##takes the fullprof and maps out matching on the workingdir. Make dest dirs
$destDir = @(Get-WMIObject Win32_UserProfile -filter "Special != 'true'" | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15)} | foreach-object {$_.localpath -replace "c:","$workingDir"})
New-Item -Path $destDir -ItemType Directory


##identify the ntuser.dats last 15 set up paths
$ntdatPaths = @(Get-ChildItem $fullProf -filter "ntuser.dat" -Force | foreach-object {$_.FullName})

$inetHist = "\AppData\Local\Microsoft\Windows\Temporary Internet Files"
New-Item -Path $destDir\$inetHist -ItemType Directory

C:\Users\********\AppData\Local\Microsoft\Windows\History


##This detects the userprofiles newer than 15 days

Get-ChildItem $fullProf -filter "ntuser.dat" -Force | Where-Object {Test-Path -Path $_.Fullname -NewerThan (Get-Date).AddDays(-15)} | foreach-object {$_.FullName} | Out-File $irFolder\users.txt

##set the latest ntuserdat files
Get-ChildItem $fullProf -filter "ntuser.dat" -Force | Where-Object {Test-Path -Path $_.Fullname -NewerThan (Get-Date).AddDays(-15)} | foreach-object {$_.FullName}



##This makes individual userprofile target folders in the $workingDir
Get-ChildItem -Path c:\users\ -Directory | Foreach {$_.Name} | foreach-object {New-Item -Path $workingDir/users/$_/ -ItemType Directory}


Copy-Item -Path $sourceList -Destination $destination -Recurse

Get-ChildItem $fullprof -filter "ntuser.dat" -Force | foreach-object -process {$_.FullName}



###################
##Package up the data and pull
###################


##7zip the artifact collection
$7z = "cmd /c $irFolder\7za.exe a $workingDir -p[xxpassxx] -mhe $workingDir.7z"
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target

##Copy off the archive to local system##
Copy-Item x:\$irFolder\*.7z C:\$workingDir


###Delete the IR folder##
Remove-Item -Recurse -Force $irFolder








