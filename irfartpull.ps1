��<#  

.SYNOPSIS  

    IR Forensic ARTifact Pull (irFArtPull)

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

Write-Host -Fore Green "Running irFArtPull............."

Write-Host -Fore Red "Run as administrator/elevated privileges!!!"

echo "++++++++++++++++++++++++++++"

echo "++++++++++++++++++++++++++++"

echo "++++++++++++++++++++++++++++"

Write-Host -Fore Green "Press a key to begin....."

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

################

##For consistentancy, the working directory will be located in the "c:\windows\temp\IR" folder on both the target and initiator sytem.

##Tools will stored directly in the "IR" folder for use. Artifacts collected on the local environment of the remote system will be dropped in the workingdir.



##Set up PSDrive mapping to remote drive

New-PSDrive -Name X -PSProvider filesystem -Root \\$target\c$



$date = Get-Date -format yyyy-MM-dd_HHmm_

$targetName = Get-WMIObject Win32_ComputerSystem -ComputerName $target | ForEach-Object Name

$remoteIRfold = "X:\windows\Temp\IR"

$irFolder = "c:\Windows\Temp\IR\"

$artFolder = $date + $targetName

$workingDir = $irFolder + $artFolder

$dirList = ("$remoteIRfold\$artFolder\logs","$remoteIRfold\$artFolder\network","$remoteIRfold\$artFolder\prefetch","$remoteIRfold\$artFolder\reg")

New-Item -Path $dirList -ItemType Directory



##connect and move software to target client

Write-Host -Fore Green "Copying tools...."

$tools = "c:\tools\resp\*.*"

Copy-Item $tools $remoteIRfold -recurse



##SystemInformation

Write-Host -Fore Green "Pulling system information...."

Get-WMIObject Win32_LogicalDisk -ComputerName $target | Select DeviceID,DriveType,@{l="Drive Size";e={$_.Size / 1GB -join ""}},@{l="Free Space";e={$_.FreeSpace / 1GB -join ""}} | Export-CSV $remoteIRfold\$artFolder\diskInfo.csv -NoTypeInformation

Get-WMIObject Win32_ComputerSystem -ComputerName $target | Select Name,UserName,Domain,Manufacturer,Model,PCSystemType | Export-CSV $remoteIRfold\$artFolder\systemInfo.csv -NoTypeInformation

Get-WmiObject Win32_UserProfile -ComputerName $target | select Localpath,SID,LastUseTime | Export-CSV $remoteIRfold\$artFolder\users.csv -NoTypeInformation



##gather network  & adapter info

Write-Host -Fore Green "Pulling network information...."

Get-WMIObject Win32_NetworkAdapterConfiguration -ComputerName $target -Filter "IPEnabled='TRUE'" | select DNSHostName,ServiceName,MacAddress,@{l="IPAddress";e={$_.IPAddress -join ","}},@{l="DefaultIPGateway";e={$_.DefaultIPGateway -join ","}},DNSDomain,@{l="DNSServerSearchOrder";e={$_.DNSServerSearchOrder -join ","}},Description | Export-CSV $remoteIRfold\$artFolder\network\netinfo.csv -NoTypeInformation



$netstat = "cmd /c c:\windows\system32\netstat.exe -anob > $workingDir\network\netstats.txt"

$netroute = "cmd /c c:\windows\system32\netstat.exe -r > $workingDir\network\routetable.txt"

$dnscache = "cmd /c c:\windows\system32\ipconfig /displaydns > $workingDir\network\dnscache.txt"

$arpdata =  "cmd /c c:\windows\system32\netstat.exe -r > $workingDir\network\arpdata.txt"



InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netstat -ComputerName $target

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $netroute -ComputerName $target

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $dnscache -ComputerName $target

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $arpdata -ComputerName $target

Copy-Item x:\windows\system32\drivers\etc\hosts $remoteIRfold\$artFolder\network\hosts 



##gather Process info

Write-Host -Fore Green "Pulling process info...."

Get-WMIObject Win32_Process -Computername $target | select name,parentprocessid,processid,executablepath,commandline | Export-CSV $remoteIRfold\$artFolder\procs.csv -NoTypeInformation



##gather Services info

Write-Host -Fore Green "Pulling service info...."

Get-WMIObject Win32_Service -Computername $target | Select processid,name,state,displayname,pathname,startmode | Export-CSV $remoteIRfold\$artFolder\services.csv -NoTypeInformation



####################

##Copy Artifacts on the Target System

####################



##Copy Log Files

Write-Host -Fore Green "Pulling event logs...."

$logLoc = "x:\windows\system32\Winevt\Logs"

$loglist = @("$logLoc\application.evtx","$logLoc\security.evtx","$logLoc\system.evtx")

Copy-Item -Path $loglist -Destination $remoteIRfold\$artFolder\logs\ -Force



##Copy Prefetch files

Write-Host -Fore Green "Pulling prefetch files...."

Copy-Item x:\windows\prefetch\*.pf $remoteIRfold\$artFolder\prefetch -recurse



##Copy MFT$

Write-Host -Fore Green "Pulling the MFT$...."

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c $irFolder\RawCopy64.exe c:0 $workingDir" -ComputerName $target



##Copy Reg files

Write-Host -Fore Green "Pulling registry files...."

$regLoc = "c:\windows\system32\config\"

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c $irFolder\RawCopy64.exe $regLoc\SOFTWARE $workingDir\reg" -ComputerName $target

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c $irFolder\RawCopy64.exe $regLoc\SYSTEM $workingDir\reg" -ComputerName $target

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c $irFolder\RawCopy64.exe $regLoc\SAM $workingDir\reg" -ComputerName $target

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c $irFolder\RawCopy64.exe $regLoc\SECURITY $workingDir\reg" -ComputerName $target



###################

##Perform Operations on user files

###################

Write-Host -Fore Green "Pulling NTUSER.DAT files...."

$localprofiles = Get-WMIObject Win32_UserProfile -filter "Special != 'true'" -ComputerName $target | Where {$_.LocalPath -and ($_.ConvertToDateTime($_.LastUseTime)) -gt (get-date).AddDays(-15) }

foreach ($localprofile in $localprofiles){

	$temppath = $localprofile.localpath

	$source = $temppath + "\ntuser.dat"

	$eof = $temppath.Length

	$last = $temppath.LastIndexOf('\')

	$count = $eof - $last

	$user = $temppath.Substring($last,$count)

	$destination = "$workingDir\users" + $user

	New-Item -Path $remoteIRfold\$artFolder\users\$user -ItemType Directory

	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c $irFolder\RawCopy64.exe $source $destination" -ComputerName $target

}



##Copy IDX files

Write-Host -Fore Green "Pulling IDX files...."

New-Item -Path $remoteIRfold\$artFolder\users\$user\idx -ItemType Directory

$idxFiles = Get-ChildItem x:\users\$user\AppData\LocalLow\Sun\Java\Deployment\cache\ -Filter "*.idx" -Force -Recurse | Where-Object {$_.Length -gt 0 -and $_.LastWriteTime -gt (get-date).AddDays(-30)} | foreach {$_.Fullname}

	foreach ($idx in $idxFiles){

	Copy-Item -Path $idx -Destination $remoteIRfold\$artFolder\users\$user\idx\

}



##Copy Internet History files

Write-Host -Fore Green "Pulling Internet History files...."

New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\IE -ItemType Directory

$inethist = Get-ChildItem X:\users\$user\AppData\Local\Microsoft\Windows\History -ReCurse -Force | foreach {$_.Fullname}

foreach ($inet in $inethist) {

Copy-Item -Path $inet -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\IE -Force -Recurse

}



##Copy FireFox History files

if (Test-Path -IsValid X:\users\$user\AppData\Roaming\Mozilla\) {

Write-Host -Fore Green "Pulling FireFox Internet History files...."

New-Item -Path $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox -ItemType Directory

$ffinet = Get-ChildItem X:\users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\ -Filter "places.sqlite" -Force -Recurse | foreach {$_.Fullname}

Foreach ($ffi in $ffinet) {

Copy-Item -Path $ffi -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox

}

$ffdown = Get-ChildItem X:\Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\ -Filter "downloads.sqlite" -Force -Recurse | foreach {$_.Fullname}

Foreach ($ffd in $ffdown) {

Copy-Item -Path $ffd -Destination $remoteIRfold\$artFolder\users\$user\InternetHistory\Firefox

}

else

{

Write-Host -Fore Red "No FireFox Internet History files...."

}

}



###################

##Package up the data and pull

###################



##7zip the artifact collection

Write-Host -Fore Green "Packaging the collection...."

$7z = "cmd /c $irFolder\7za.exe a $workingDir -p[xxpassxx] -mhe $workingDir.7z"

InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target



##Copy off the archive to local system##

Write-Host -Fore Green "Pulling the Analysis Package...."

Import-Module BitsTransfer

Copy-Item X:\$irFolder\*.7z $workingDir

Complete-BitsTransfer



###Delete the IR folder##

Write-Host -Fore Green "Removing the collection environment...."

Remove-Item -Recurse -Force $irFolder



##Ending

Write-Host -Fore Green "irFArtPull complete...."





