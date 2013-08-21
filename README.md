IR Forensic ARTifact pull (irFArtpull)

DESCRIPTION:

irFARTpull is a PowerShell script utilized to pull several forensic artifacts from a live Win7x64 system on your network. 
		
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
- Registry Files
- User NTUSER.dat files
- Java IDX files
- Internet History Files (IE, Firefox, Chrome)
	
When done collecting the artifacts, it will 7zip the data and yank the info off the box for off-line analysis. 
		
NOTEs: 
- All testing done on PowerShell v3
- Tested only on Windows 7 x64. (future versions will feature x86 and XP detections
- Requires RawCopy64.exe for the extraction of MFT$ and NTUSER.DAT files.
- Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
Assumed Directories:
- c:\tools\resp\ - where the RawCopy64.exe and 7za.exe exist
- c:\windows\temp\IR - Where the work will be done
		
***As expected: Must be ran a user that will have Admin creds on the remote system. The assumption is that the target system is part of a domain.
	
LINKs:  
	
irFARTpull main - https://github.com/n3l5/irFARTpull
	
Links to required tools:
- mft2csv - Part of the mft2csv suite, RawCopy can be downloaded here: https://code.google.com/p/mft2csv/
- 7-Zip - Part of the 7-Zip archiver, 7za can be downloaded from here: http://www.7-zip.org/
	
Various tools for analysis of the artifacts:
- RegRipper - Tool for extracting data from Registry and NTUSER.dat files. https://code.google.com/p/regripper/
- WinPrefetchView - utility to read Prefetch files. http://www.nirsoft.net/utils/win_prefetch_view.html
- MFTDump - tool to dump the contents of the $MFT. http://malware-hunters.net/2012/09/