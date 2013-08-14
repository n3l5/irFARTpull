<#  
.SYNOPSIS  
    Forensic ARTifact Pull (FARTPull)
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
echo "Running fartpull............."
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

##Set up environment on remote system. IR folder for tools and art folder for artifacts.
##For consistentancy, the working directory will be located in the "c:\windows\temp\IR" folder on both the target and initiator sytem.
$date = Get-Date -format yyyy-MM-dd_HHmm_
$targetName = Get-WMIObject Win32_ComputerSystem -ComputerName $target | ForEach-Object Name
$irFolder = "c:\windows\temp\IR\"
$artFolder = $date + $targetName
$workingDir = $irFolder + $artFolder
$makRemDir = "cmd /c mkdir $workingDir"
New-Item -Path $workingDir -ItemType Directory
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $makRemDir -ComputerName $target


##connect and move software to target client
$tools = "c:\tools\resp\*.*"
Copy-Item $tools $irFolder -recurse

##SystemInformation
Get-WMIObject Win32_LogicalDisk -ComputerName $target | Select DeviceID,DriveType,@{l="Drive Size";e={$_.Size / 1GB -join ""}},@{l="Free Space";e={$_.FreeSpace / 1GB -join ""}} | Export-CSV $workingDir\diskInfo.csv -NoTypeInformation
Get-WMIObject Win32_ComputerSystem -ComputerName $target | Select Name,UserName,Domain,Manufacturer,Model,PCSystemType | Export-CSV $workingDir\systemInfo.csv -NoTypeInformation
Get-WmiObject Win32_UserProfile -ComputerName $target | select Localpath,SID,LastUseTime | Export-CSV $workingDir\users.csv -NoTypeInformation


##gather network  & adapter info
Get-WMIObject Win32_NetworkAdapterConfiguration -ComputerName $target -Filter "IPEnabled='TRUE'" | select DNSHostName,ServiceName,MacAddress,@{l="IPAddress";e={$_.IPAddress -join ","}},@{l="DefaultIPGateway";e={$_.DefaultIPGateway -join ","}},DNSDomain,@{l="DNSServerSearchOrder";e={$_.DNSServerSearchOrder -join ","}},Description | Export-CSV $workingDir\netinfo.csv -NoTypeInformation

$netstat = "cmd /c c:\windows\system32\netstat.exe -anob > $workingDir\netstats.txt"
$netroute = "cmd /c c:\windows\system32\netstat.exe -r > $workingDir\routetable.txt"
$arpdata =  "cmd /c c:\windows\system32\netstat.exe -r > $workingDir\arpdata.txt"
$hostsFileEntries = Get-Content "C:\Windows\system32\drivers\etc\hosts"
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netstat -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netroute -ComputerName $target
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $arpdata -ComputerName $target

##gather Process info
Get-WMIObject Win32_Process -Computername $target | select name,parentprocessid,processid,executablepath,commandline | Export-CSV $workingDir\procs.csv -NoTypeInformation

##gather Services info
Get-WMIObject Win32_Service -Computername $target | Select processid,name,state,displayname,pathname,startmode | Export-CSV $workingDir\services.csv -NoTypeInformation


####################
##Copy Artifacts on the Target System
####################

##Setup RawCopy
$rawcopy = "cmd /c $irFolder\RawCopy64.exe $_.Fullname  $irFolder"


##Copy Reg files
$regLoc = "c:\windows\system32\config"
$netstat = "cmd /c c:\windows\system32\netstat.exe -anob > $workingDir\netstats.txt"
$netstat = "cmd /c c:\windows\system32\netstat.exe -anob > $workingDir\netstats.txt"



SOFTWARE
SECURITY
SYSTEM
SAM



###################
##Perform Operations on user files
###################

Filter out special accounts profiles....
Get-WMIObject Win32_UserProfile -filter "Special != 'true'"



$fullProf = Get-WmiObject Win32_UserProfile | where {$_.localpath -like "c:\users\*"} | select localpath | foreach-object {$_.localpath}
$sourceList = ("$userProf\ntuser.dat","$userProf\AppData\Local\Microsoft\Windows\History\*.*","$sourceVol\windows\Prefetch","$sourceVol\windows\system32\config")

$destDir = Get-WmiObject Win32_UserProfile | where {$_.localpath -like "c:\users\*"} | foreach-object {$_.localpath -replace "c:","$irFolder"}


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
$7z = "cmd /c $irFolder\7za.exe a $workingDir -pCba321Zp! -mhe $workingDir.7z"
InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target

##Copy off the archive to local system##
Copy-Item $target\$irFolder\*.7z C:\$irFolder


###Delete the IR folder##
Remove-Item -Recurse -Force $irFolder








