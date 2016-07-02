
  _      ______           _               _ _ 
 (_)    |  ____/\        | |             | | |
  _ _ __| |__ /  \   _ __| |_ _ __  _   _| | |
 | | '__|  __/ /\ \ | '__| __| '_ \| | | | | |
 | | |  | | / ____ \| |  | |_| |_) | |_| | | |
 |_|_|  |_|/_/    \_\_|   \__| .__/ \__,_|_|_|
                             | |              
                             |_| 

IR Forensic ARTifact pull (irFArtpull)

DESCRIPTION:

irFArtpull is a PowerShell script utilized to pull several forensic artifacts from a live Windows 7, 8, Server 2008, and Server 2012 systems on your network. 
		
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
- $MFT
- NTFS $LogFile
- USN Journal
- Amcache.hve
- Registry Files
- User NTUSER.dat files (from user profiles used within last 15 days)
- Internet History Files (IE, Firefox, Chrome from user profiles used within last 15 days)
	
When done collecting the artifacts, it will 7zip the data and yank the info off the box for off-line analysis. 
		
NOTEs: 
- All testing done on PowerShell v4
- Requires RawCopy64.exe for the extraction of "in use" files.
- Requires ExtractUsnJrnl for the extraction of 
- Autorunsc - Command line version of Autoruns; shows the programs configure to run during login, system bootup, and application plug-ins.
- Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
Assumed Directories:
- c:\windows\temp\IR - Where the work will be done (no need to create)
		
***As expected: Must be ran a user that will have Admin creds on the remote system. The assumption is that the target system is part of a domain.
	
LINKs:  
	
irFARTpull main - https://github.com/n3l5/irFARTpull
	
Links to required tools:
- RawCopy.exe & RawCopy64.exe - https://github.com/jschicht/RawCopy
- ExtractUsnJrnl.exe - https://github.com/jschicht/ExtractUsnJrnl
- Autorunsc - Command line version of Autoruns; shows the programs configure to run during login, system bootup, and application plug-ins. https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx
- 7za.exe - Part of the 7-Zip archiver, 7za can be downloaded from here: http://www.7-zip.org/
	
Various tools for analysis of the artifacts:
- RegRipper - Tool for extracting data from Registry and NTUSER.dat files. https://code.google.com/p/regripper/
- PECmd - utility to parse Prefetch files. http://binaryforay.blogspot.com/2016/01/pecmd-v0600-released.html
- MFTDump - tool to dump the contents of the $MFT. http://malware-hunters.net/2012/09/
- LogParser - tool to parse event logs (and more) https://technet.microsoft.com/en-us/scriptcenter/dd919274.aspx
- Triforce ANJP - tool to examining the MFT, LogFile, and USN. https://www.gettriforce.com/product/anjp-free/
- Cold Disk Quick Response (CDQR) - forensic artifact parsing tool that works on extracted artifacts. https://github.com/rough007/CDQR
**Since IRFartpull pulls raw files you can use whatever tool(s) you want.