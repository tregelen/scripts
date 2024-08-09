#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

#region Import Registry Information
# Imports information from the registry
$XML = Get-ItemProperty "HKLM:\SOFTWARE\ServiceDeskNotifier\"


$BackgroundImage = $XML.BackgroundImage
$BackgroundColour = $XML.BackgroundColour
$EmailAddress = $XML.EmailAddress
$AdditionalInformation = $XML.Hours

$registryPath = "HKCU:\Software\ServiceDeskNotifier"
If (!(Test-Path $registryPath))
{
	New-Item -Path $registryPath -Force | Out-Null
}

#endregion

<#
	.SYNOPSIS
		Gets the information about the machine
	
	.DESCRIPTION
		Gets all the information about the current machine for display on the form
	
	.EXAMPLE
		PS C:\> Get-Information

#>
function Get-Information
{
	[CmdletBinding()]
	param ()
	$global:EmailBody = ""
	$richtextboxSummary.text = ""
	$Win32_ComputerSystem = (Get-CimInstance -ClassName Win32_ComputerSystem)
	#$Win32_NetworkAdapter = (Get-CimInstance -ClassName Win32_networkadapter | Select-Object Name, MacAddress)
	$Win32_SystemEnclosure = (Get-CimInstance -ClassName Win32_SystemEnclosure | Select-Object SMBiosAssetTag, SerialNumber)
	#$Win32_BIOS = (Get-CimInstance -ClassName Win32_bios | Select-Object SMBIOSBIOSVersion)
	#$Win32_NetworkAdapterConfiguration = (Get-CimInstance -ClassName Win32_networkadapterconfiguration -property IPAddress, Description, MACAddress | Where-Object ipaddress -ne $null | Select-Object IPAddress, Description, MACAddress)
	$Win32_NetworkAdapterConfiguration = (Get-CimInstance -ClassName Win32_networkadapterconfiguration -property IPAddress, Description, MACAddress | Where-Object MACAddress -ne $null  | Select-Object IPAddress, Description, MACAddress)
	
	#$Win32_ComputerSystemProduct = (Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object UUID)
	$Win32_LogicalDisk = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {
		($_.DriveType -EQ 3) -OR ($_.DriveType -EQ 2) -OR ($_.DriveType -EQ 4)
	} | Select-Object DeviceID, FreeSpace, Size, ProviderName, DriveType
	$Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -Property * | Select-Object Caption, ServicePackMajorVersion, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate
	#$Win32_Processor = Get-CimInstance -ClassName Win32_Processor | Select-Object Name
	$Win32_PhysicalMemoryArray = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | Select-Object Sum
	$Win32_Printer = Get-CimInstance -Classname Win32_Printer | Select-Object Name, SystemName, PrinterStatus
	
	$nfi = New-Object System.Globalization.CultureInfo -ArgumentList "en-us", $false
	$nfi.NumberFormat.PercentDecimalDigits = 2
	
	<# Get ComputerSystem information, includes:
		Computer Name
		Current User
		Manufacturer
		Model
		RAM
	#>
	$Win32_ComputerSystem | ForEach-Object {
		$richtextboxSummary.appendtext("Computer Name:	$($_.Name)")
		$richtextboxSummary.appendtext("`nCurrent User:		$($_.Username)")
		$richtextboxSummary.appendtext("`nManufacturer:		$($_.Manufacturer)")
		$richtextboxSummary.appendtext("`nModel:			$($_.Model)")
		$richtextboxSummary.appendtext("`nRAM:			$(($_.TotalPhysicalMemory/1GB).ToString("N", $nfi)) GB/$(($Win32_PhysicalMemoryArray.Sum/1GB).ToString("N", $nfi)) GB")
		$Global:EmailBody += "<br>Computer Name:	$($_.Name)"
		$Global:EmailBody += "<br>Current User:		$($_.Username)"
		$Global:EmailBody += "<br>Manufacturer:		$($_.Manufacturer)"
		$Global:EmailBody += "<br>Model:			$($_.Model)"
		$Global:EmailBody += "<br>RAM:			$(($_.TotalPhysicalMemory/1GB).ToString("N", $nfi)) GB/$(($Win32_PhysicalMemoryArray.Sum/1GB).ToString("N", $nfi)) GB"
		
	}
	
	<# Get SystemEnclosure information, includes:
		Asset Number
		Serial
	#>
	
	$Win32_SystemEnclosure | ForEach-Object {
		$richtextboxSummary.appendtext("`nAsset Number:		$($_.SMBiosAssetTag)")
		$richtextboxSummary.appendtext("`nSerial:		$($_.SerialNumber)")
		$global:EmailBody += "<br>Asset Number:		$($_.SMBiosAssetTag)"
		$global:EmailBody += "<br>Serial:		$($_.SerialNumber)"
	}
	
	<# Get ComputerSystemProduct information, includes:
		UUID/SMBIOSGUID
	#>
	<#$Win32_ComputerSystemProduct | ForEach-Object {
		$richtextboxSummary.appendtext("`nUUID/SMBIOSGUID:	$($_.UUID)")
		$global:EmailBody += "<br>UUID/SMBIOSGUID:	$($_.UUID)"
	}
	#>
	<# Get Processor information, includes:
		CPU
	#>
	<#
	$Win32_Processor | ForEach-Object {
		$richtextboxSummary.appendtext("`nCPU:			$($_.Name)")
		$global:EmailBody += "<br>CPU:			$($_.Name)"
	}
	#>
	
	<# Get LogicalDisk information, includes:
		Local Disks:
			Drive Letter
			Free Space
			Total Size
		
		Mapped Drive/Network Drive:
			Drive Letter
			Path
	#>
	$Drives = @()
	$NetworkDrives = @()
	$RegistryNetworkDrives = Get-ItemProperty -path $registryPath
	
	$Win32_LogicalDisk | ForEach-Object {
		if ($_.DriveType -eq 4)
		{
			
			if ($RegistryNetworkDrives.($_.DeviceID) -ne ($_.ProviderName))
			{
				$Status = 'Synced'
			}else{ $Status = 'Unsynced'}
			
			
			$NetworkDrives += [PSCustomObject]@{
				'Drive Letter'  = ($_.DeviceID)
				Location		= ($_.ProviderName)
				'Status'		= $status
			}
			New-ItemProperty -Path $registryPath -Name ($_.DeviceID) -Value ($_.ProviderName) -PropertyType String -Force | Out-Null
		}
		else
		{
			$Drives += [PSCustomObject]@{
				'Drive Letter'   = ($_.DeviceID)
				'Free Space'	 = "$(($_.FreeSpace/1GB).ToString("N", $nfi)) GB"
				'Size'		     = "$(($_.Size/1GB).ToString("N", $nfi)) GB"
			}
		}
	}
	
	
	
	
	
	$richtextboxSummary.appendtext("`n`nHard Disks:`n$($Drives | Format-Table -AutoSize -Wrap | Out-String)Network Drives:`n$($NetworkDrives | Format-Table -AutoSize -Wrap | Out-String)")
	
	$global:EmailBody += "<br><br><table>
		<caption>Hard Disk/s</caption>
		<tr>
		    <th>Drive Letter</th>
		    <th>Free Space</th> 
		    <th>Size</th>
		</tr>"
	$Drives | ForEach-Object { $global:EmailBody += "<tr><td>$($_."Drive Letter")</td><td>$($_."Free Space")</td><td>$($_.Size)<td><tr>" }
	$Global:EmailBody += "</table>"
	$global:EmailBody += "<br><br><table>
		<caption>Network Drives</caption>
		<tr>
			<th>Drive Letter</th>
		    <th>Path</th> 
		</tr>"
	
	
	
	
	$NetworkDrives | ForEach-Object {
		$global:EmailBody += "<tr><td>$($_."Drive Letter")</td><td>$($_.Location)<td><tr>"
	}
	$global:EmailBody += "</table>"
	
	
	
	
	
	<# Get NetworkAdapterConfiguration information, includes:
		Adaptor Name
		MAC Address
		IP Address
	#>
	
	$NetworkAdaptors = @()
	$Win32_NetworkAdapterConfiguration | ForEach-Object {
		$NetworkAdaptors += [PSCustomObject]@{
			'Adaptor Name' = ($_.Description)
			'MAC Address' = ($_.MacAddress)
			'IP Address' = $($_.IPAddress[0])
		}
	}
	$richtextboxSummary.appendtext("`nNetwork Adaptor:$($NetworkAdaptors | Format-Table -AutoSize -Wrap | Out-String)")
	
	$global:EmailBody += "<br><br><table>
		<caption>Network Adaptor/s</caption>
		<tr>
			<th>Adaptor Name</th>
			<th>MAC Address</th> 
			<th>IP Address</th>
		</tr>"
	$NetworkAdaptors | ForEach-Object { $global:EmailBody += "<tr><td>$($_."Adaptor Name")</td><td>$($_."MAC Address")</td><td>$($_."IP Address")<td><tr>" }
	
	$global:EmailBody += "</table>"
	
	$Printers = @()
	$Win32_Printer | ForEach-Object {
		$Status = switch ($_.PrinterStatus)
		{
			1 { "Other" }
			2 { "Unknown" }
			3 { "Idle" }
			4 { "Printing" }
			5 { "Warming Up" }
			6 { "Stopped Printing" }
			7 { "Offline" }
			8 { "Paused" }
			9 { "Error" }
			10{ "Busy" }
			11{ "Not Available" }
			12{ "Waiting" }
			13{ "Processing" }
			14{ "Initialization" }
			15{ "Power Save" }
			16{ "Pending Deletion" }
			17{ "I/O Active" }
			18{ "Manual Feed" }
		}
		$Printers += [PSCustomObject]@{
			Name = ($_.Name)
			SystemName = ($_.SystemName)
			Status = $Status
		}
	}
	
	$richtextboxSummary.appendtext("`nPrinters:$($Printers | Format-Table -AutoSize -Wrap | Out-String)")
	
	$global:EmailBody += "<br><br><table>
		<caption>Printer/s</caption>
		<tr>
			<th>Name</th>
			<th>System Name</th>
			<th>Status</th>
		</tr>"
	$Printers | ForEach-Object { $global:EmailBody += "<tr><td>$($_.Name)</td><td>$($_.SystemName)</td><td>$($_.Status)<td><tr>" }
	
	$Global:EmailBody += "</table>"
	
	
	
	$richtextboxSummary.appendtext("Operating System:")
	$Global:EmailBody += "<br><br>Operating System:"
	$Win32_OperatingSystem | ForEach-Object {
		$richtextboxSummary.appendtext("`n$($_.Caption)")
		$richtextboxSummary.appendtext("`nService Pack:		$($_.ServicePackMajorVersion)")
		$richtextboxSummary.appendtext("`nBuild Number:		$($_.BuildNumber)")
		$richtextboxSummary.appendtext("`nOS Architecture:	$($_.OSArchitecture)")
		$richtextboxSummary.appendtext("`nLast Boot Time:	$($_.LastBootUpTime)")
		$richtextboxSummary.appendtext("`nInstall Date:		$($_.InstallDate)")
		
		$Global:EmailBody += "<br>$($_.Caption)"
		$Global:EmailBody += "<br>Service Pack:		$($_.ServicePackMajorVersion)"
		$Global:EmailBody += "<br>Build Number:		$($_.BuildNumber)"
		$Global:EmailBody += "<br>OS Architecture:	$($_.OSArchitecture)"
		$Global:EmailBody += "<br>Last Boot Time:	$($_.LastBootUpTime)"
		$Global:EmailBody += "<br>Install Date:		$($_.InstallDate)"
	}
}

$processTracker_FormClosed = [System.Windows.Forms.FormClosedEventHandler]{
	#Stop any pending processes
	Stop-ProcessTracker
}

$timerProcessTracker_Tick = {
	Update-ProcessTracker
}

function Get-EventLogs
{
	[CmdletBinding()]
	param ()
	if ((Test-Path -Path "$env:TEMP\SDNLogs\"))
	{
		Remove-Item -Path "$env:TEMP\SDNLogs\*" -Force
		Remove-Item -Path "$env:TEMP\SDNLogs\" -Force
	}
	
	New-Item -Path "$env:TEMP\SDNLogs\" -ItemType Directory
	Get-EventLog -LogName Application -After (Get-Date).AddHours(- $AdditionalInformation) | ForEach-Object { Write-Log -message $_.Message -Source $_.Source -ScriptSection "ApplicationLog" -LogFileDirectory $env:TEMP\SDNLogs -LogFileName Applicationlog.log -WriteHost $false -LogDebugMessage $false -LogType CMTrace }
	Get-EventLog -LogName System -After (Get-Date).AddHours(- $AdditionalInformation) | ForEach-Object { Write-Log -message $_.Message -Source $_.Source -ScriptSection "SystemLog" -LogFileDirectory $env:TEMP\SDNLogs -LogFileName Systemlog.log -WriteHost $false -LogDebugMessage $false -LogType CMTrace }
	ZipFiles -SourceDir $env:TEMP\SDNLogs\ -ZipFileName $env:TEMP\SDNLogs.zip
	Move-Item -Path $env:TEMP\SDNLogs.zip -Destination $env:TEMP\SDNLogs\
}

function Generate-Email
{
	[CmdletBinding()]
	param
	(
		[boolean]$Attachment
	)
	
	$outlook = New-Object -comObject Outlook.Application
	$mail = $outlook.CreateItem(0)
	$mail.Recipients.Add($EmailAddress)
	$mail.Subject = "### INSERT DESCRIPTION OF ISSUE ###"
	$mail.HTMLBody = "<HTML><BODY>Add Description of issue here
		<br>
		<br>
		<br>
		<br>
		<B>####################
		<br>DO NOT CHANGE ANY OF THE BELOW, DOING SO MAY PREVENT YOUR ISSUE BEING LOGGED CORRECTLY
		<br>####################</B>
		<br>$global:EmailBody
		</BODY>
		</HTML>"
	
	If ((Test-Path -Path "$env:TEMP\SDNLogs\SDNLogs.zip"))
	{
		$mail.Attachments.Add("$env:TEMP\SDNLogs\SDNLogs.zip")
		Remove-Item -Path "$env:TEMP\SDNLogs\*" -Force
		Remove-Item -Path "$env:TEMP\SDNLogs\" -Force
	}
	
	$Mail.Display()
}

#region Process Tracker
$ProcessTrackerList = New-Object System.Collections.ArrayList

function Add-ProcessTracker
{
	<#
		.SYNOPSIS
			Add a new process to the ProcessTracker and starts the timer.
	
		.DESCRIPTION
			Add a new process to the ProcessTracker and starts the timer.
	
		.PARAMETER  FilePath
			The path to executable.
	
		.PARAMETER ArgumentList
			The arguments to pass to the process.
	
		.PARAMETER  CompleteScript
			The script block that will be called when the process is complete.
			The process is passed as an argument. The process argument is null when the job fails.
	
		.PARAMETER  UpdateScript
			The script block that will be called each time the timer ticks.
			The process is passed as an argument.
	
		.EXAMPLE
			 Add-ProcessTracker -FilePath "$env:windir/System32/notepad.exe" `
			-CompletedScript {
				Param([System.Diagnostics.Process]$Process)
				$button.Enable = $true
			}`
			-UpdateScript {
				Param([System.Diagnostics.Process]$Process)
				Function-Animate $button
			}
	
		.LINK
			
	#>
	
	Param (
		[ValidateNotNull()][Parameter(Mandatory = $true)][string]$FilePath,
		$ArgumentList = $null,
		[ScriptBlock]$CompletedScript,
		[ScriptBlock]$UpdateScript)
	
	#Start the Job
	if ($ArgumentList)
	{
		$process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
	}
	else
	{
		$process = Start-Process -FilePath $FilePath -PassThru
	}
	
	if ($null -ne $process)
	{
		#Create a Custom Object to keep track of the Job & Script Blocks
		$members = @{
			"Process" = $process;
			"CompleteScript" = $CompletedScript;
			"UpdateScript" = $UpdateScript
		}
		
		$psObject = New-Object System.Management.Automation.PSObject -Property $members
		
		[void]$ProcessTrackerList.Add($psObject)
		
		#Start the Timer
		if (-not $timerProcessTracker.Enabled)
		{
			$timerProcessTracker.Start()
		}
	}
	elseif ($null -ne $CompletedScript)
	{
		#Failed
		Invoke-Command -ScriptBlock $CompletedScript -ArgumentList $null
	}
	
}

function Update-ProcessTracker
{
	<#
		.SYNOPSIS
			Checks the status of each job on the list.
	#>
	
	#Poll the jobs for status updates
	$timerProcessTracker.Stop() #Freeze the Timer
	
	for ($index = 0; $index -lt $ProcessTrackerList.Count; $index++)
	{
		$psObject = $ProcessTrackerList[$index]
		
		if ($null -ne $psObject)
		{
			if ($null -ne $psObject.Process)
			{
				if ($psObject.Process.HasExited)
				{
					#Call the Complete Script Block
					if ($null -ne $psObject.CompleteScript)
					{
						#$results = Receive-Job -Job $psObject.Job
						Invoke-Command -ScriptBlock $psObject.CompleteScript -ArgumentList $psObject.Process
					}
					
					$ProcessTrackerList.RemoveAt($index)
					$index-- #Step back so we don't skip a job
				}
				elseif ($null -ne $psObject.UpdateScript)
				{
					#Call the Update Script Block
					Invoke-Command -ScriptBlock $psObject.UpdateScript -ArgumentList $psObject.Process
				}
			}
		}
		else
		{
			$ProcessTrackerList.RemoveAt($index)
			$index-- #Step back so we don't skip a job
		}
	}
	
	if ($ProcessTrackerList.Count -gt 0)
	{
		$timerProcessTracker.Start() #Resume the timer	
	}
}

function Stop-ProcessTracker
{
	<#
		.SYNOPSIS
			Stops and removes all processes from the list.
	#>
	#Stop the timer
	$timerProcessTracker.Stop()
	
	#Remove all the processes
	while ($ProcessTrackerList.Count -gt 0)
	{
		$process = $ProcessTrackerList[0].Process
		$ProcessTrackerList.RemoveAt(0)
		if (-not $psObject.Process.HasExited)
		{
			Stop-Process -InputObject $process
		}
	}
}
#endregion

#region Control Helper Functions
function Show-NotifyIcon
{
<#
	.SYNOPSIS
		Displays a NotifyIcon's balloon tip message in the taskbar's notification area.
	
	.DESCRIPTION
		Displays a NotifyIcon's a balloon tip message in the taskbar's notification area.
		
	.PARAMETER NotifyIcon
     	The NotifyIcon control that will be displayed.
	
	.PARAMETER BalloonTipText
     	Sets the text to display in the balloon tip.
	
	.PARAMETER BalloonTipTitle
		Sets the Title to display in the balloon tip.
	
	.PARAMETER BalloonTipIcon	
		The icon to display in the ballon tip.
	
	.PARAMETER Timeout	
		The time the ToolTip Balloon will remain visible in milliseconds. 
		Default: 0 - Uses windows default.
#>
	param (
		[Parameter(Mandatory = $true, Position = 0)][ValidateNotNull()][System.Windows.Forms.NotifyIcon]$NotifyIcon,
		[Parameter(Mandatory = $true, Position = 1)][ValidateNotNullOrEmpty()][String]$BalloonTipText,
		[Parameter(Position = 2)][String]$BalloonTipTitle = '',
		[Parameter(Position = 3)][System.Windows.Forms.ToolTipIcon]$BalloonTipIcon = 'None',
		[Parameter(Position = 4)][int]$Timeout = 0
	)
	
	if ($null -eq $NotifyIcon.Icon)
	{
		#Set a Default Icon otherwise the balloon will not show
		$NotifyIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon([System.Windows.Forms.Application]::ExecutablePath)
	}
	
	$NotifyIcon.ShowBalloonTip($Timeout, $BalloonTipTitle, $BalloonTipText, $BalloonTipIcon)
}


#endregion

#region Function Write-Log
Function Write-Log
{
<#
.SYNOPSIS
	Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.
.DESCRIPTION
	Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.
.PARAMETER Message
	The message to write to the log file or output to the console.
.PARAMETER Severity
	Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
	Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)
.PARAMETER Source
	The source of the message being logged.
.PARAMETER ScriptSection
	The heading for the portion of the script that is being executed. Default is: $script:installPhase.
.PARAMETER LogFileDirectory
	Set the directory where the log file will be saved.
.PARAMETER LogFileName
	Set the name of the log file.
.PARAMETER MaxLogFileSizeMB
	Maximum file size limit for log file in megabytes (MB). Default is 10 MB.
.PARAMETER WriteHost
	Write the log message to the console.
.PARAMETER ContinueOnError
	Suppress writing log message to console on failure to write message to log file. Default is: $true.
.PARAMETER PassThru
	Return the message that was passed to the function
.PARAMETER DebugMessage
	Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.
.PARAMETER LogDebugMessage
	Debug messages only get logged if this parameter is set to $true in the config XML file.
.EXAMPLE
	Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'
.EXAMPLE
	Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][AllowEmptyCollection()][Alias('Text')][string[]]$Message,
		[Parameter(Mandatory = $false, Position = 1)][ValidateRange(1, 3)][int16]$Severity = 1,
		[Parameter(Mandatory = $false, Position = 2)][ValidateNotNull()][string]$Source = '',
		[Parameter(Mandatory = $false, Position = 3)][ValidateNotNullorEmpty()][string]$ScriptSection = $script:installPhase,
		[Parameter(Mandatory = $false, Position = 4)][ValidateSet('CMTrace', 'Legacy')][string]$LogType = $configToolkitLogStyle,
		[Parameter(Mandatory = $false, Position = 5)][ValidateNotNullorEmpty()][string]$LogFileDirectory = $(If ($configToolkitCompressLogs) { $logTempFolder }
			Else { $configToolkitLogDir }),
		[Parameter(Mandatory = $false, Position = 6)][ValidateNotNullorEmpty()][string]$LogFileName = $logName,
		[Parameter(Mandatory = $false, Position = 7)][ValidateNotNullorEmpty()][decimal]$MaxLogFileSizeMB = $configToolkitLogMaxSize,
		[Parameter(Mandatory = $false, Position = 8)][ValidateNotNullorEmpty()][boolean]$WriteHost = $configToolkitLogWriteToHost,
		[Parameter(Mandatory = $false, Position = 9)][ValidateNotNullorEmpty()][boolean]$ContinueOnError = $true,
		[Parameter(Mandatory = $false, Position = 10)][switch]$PassThru = $false,
		[Parameter(Mandatory = $false, Position = 11)][switch]$DebugMessage = $false,
		[Parameter(Mandatory = $false, Position = 12)][boolean]$LogDebugMessage = $configToolkitLogDebugMessage
	)
	
	Begin
	{
		## Get the name of this function
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		
		## Logging Variables
		#  Log file date/time
		[string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
		[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
		If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) { [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes }
		[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
		#  Initialize variables
		[boolean]$ExitLoggingFunction = $false
		If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) { $DisableLogging = $false }
		#  Check if the script section is defined
		[boolean]$ScriptSectionDefined = [boolean](-not [string]::IsNullOrEmpty($ScriptSection))
		#  Get the file name of the source script
		Try
		{
			If ($script:MyInvocation.Value.ScriptName)
			{
				[string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
			}
			Else
			{
				[string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
			}
		}
		Catch
		{
			$ScriptSource = ''
		}
		
		## Create script block for generating CMTrace.exe compatible log entry
		[scriptblock]$CMTraceLogString = {
			Param (
				[string]$lMessage,
				[string]$lSource,
				[int16]$lSeverity
			)
			"<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
		}
		
		## Create script block for writing log entry to the console
		[scriptblock]$WriteLogLineToHost = {
			Param (
				[string]$lTextLogLine,
				[int16]$lSeverity
			)
			If ($WriteHost)
			{
				#  Only output using color options if running in a host which supports colors.
				If ($Host.UI.RawUI.ForegroundColor)
				{
					Switch ($lSeverity)
					{
						3 { Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black' }
						2 { Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
						1 { Write-Host -Object $lTextLogLine }
					}
				}
				#  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
				Else
				{
					Write-Output -InputObject $lTextLogLine
				}
			}
		}
		
		## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
		If (($DebugMessage) -and (-not $LogDebugMessage)) { [boolean]$ExitLoggingFunction = $true; Return }
		## Exit function if logging to file is disabled and logging to console host is disabled
		If (($DisableLogging) -and (-not $WriteHost)) { [boolean]$ExitLoggingFunction = $true; Return }
		## Exit Begin block if logging is disabled
		If ($DisableLogging) { Return }
		## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
		If (($AsyncToolkitLaunch) -and ($ScriptSection -eq 'Initialization')) { [boolean]$ExitLoggingFunction = $true; Return }
		
		## Create the directory where the log file will be saved
		If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container'))
		{
			Try
			{
				$null = New-Item -Path $LogFileDirectory -ItemType 'Directory' -Force -ErrorAction 'Stop'
			}
			Catch
			{
				[boolean]$ExitLoggingFunction = $true
				#  If error creating directory, write message to console
				If (-not $ContinueOnError)
				{
					Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
				}
				Return
			}
		}
		
		## Assemble the fully qualified path to the log file
		[string]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
	}
	Process
	{
		## Exit function if logging is disabled
		If ($ExitLoggingFunction) { Return }
		
		ForEach ($Msg in $Message)
		{
			## If the message is not $null or empty, create the log entry for the different logging methods
			[string]$CMTraceMsg = ''
			[string]$ConsoleLogLine = ''
			[string]$LegacyTextLogLine = ''
			If ($Msg)
			{
				#  Create the CMTrace log message
				If ($ScriptSectionDefined) { [string]$CMTraceMsg = "[$ScriptSection] :: $Msg" }
				
				#  Create a Console and Legacy "text" log entry
				[string]$LegacyMsg = "[$LogDate $LogTime]"
				If ($ScriptSectionDefined) { [string]$LegacyMsg += " [$ScriptSection]" }
				If ($Source)
				{
					[string]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
					Switch ($Severity)
					{
						3 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg" }
						2 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg" }
						1 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg" }
					}
				}
				Else
				{
					[string]$ConsoleLogLine = "$LegacyMsg :: $Msg"
					Switch ($Severity)
					{
						3 { [string]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg" }
						2 { [string]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg" }
						1 { [string]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg" }
					}
				}
			}
			
			## Execute script block to create the CMTrace.exe compatible log entry
			[string]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity
			
			## Choose which log type to write to file
			If ($LogType -ieq 'CMTrace')
			{
				[string]$LogLine = $CMTraceLogLine
			}
			Else
			{
				[string]$LogLine = $LegacyTextLogLine
			}
			
			## Write the log entry to the log file if logging is not currently disabled
			If (-not $DisableLogging)
			{
				Try
				{
					$LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
				}
				Catch
				{
					If (-not $ContinueOnError)
					{
						Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
					}
				}
			}
			
			## Execute script block to write the log entry to the console if $WriteHost is $true
			& $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
		}
	}
	End
	{
		## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
		Try
		{
			If ((-not $ExitLoggingFunction) -and (-not $DisableLogging))
			{
				[IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
				[decimal]$LogFileSizeMB = $LogFile.Length/1MB
				If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0))
				{
					## Change the file extension to "lo_"
					[string]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
					[hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }
					
					## Log message about archiving the log file
					$ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
					Write-Log -Message $ArchiveLogMessage @ArchiveLogParams
					
					## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
					Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'
					
					## Start new log file and Log message about archiving the old log file
					$NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
					Write-Log -Message $NewLogMessage @ArchiveLogParams
				}
			}
		}
		Catch
		{
			## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
		}
		Finally
		{
			If ($PassThru) { Write-Output -InputObject $Message }
		}
	}
}
#endregion

function ZipFiles
{
	param (
		[string]$ZipFileName,
		[string]$SourceDir
	)
	
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	[System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDir, $ZipFileName, $compressionLevel, $false)
}