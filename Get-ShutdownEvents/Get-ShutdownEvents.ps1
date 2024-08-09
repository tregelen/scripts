$DeviceName = ""

$Results = Invoke-Command -ComputerName $DeviceName -ScriptBlock {
    $Return = @()
    $ShutdownLogs = Get-WinEvent -FilterHashtable @{logname = 'System'; id = 1074 }
    foreach ($Shutdown in $ShutdownLogs) {
        $LastShutdownTime = $Shutdown.TimeCreated
        $MessageSearch = "on behalf of user"
        $MessageSearchEnd = "for the following reason"
        $index = $Shutdown.Message.IndexOf($MessageSearch)
        $indexEnd = $Shutdown.Message.IndexOf($MessageSearchEnd)
        $LastShutdownUser = ($Shutdown.Message.Substring($index + $MessageSearch.Length, $indexEnd - $index - $MessageSearch.Length)).Trim()

        $TempShutdown = [PSCustomObject]@{
            Time = $LastShutdownTime
            User = $LastShutdownUser
        }
        $Return += $TempShutdown
    }

    Write-Output -InputObject $Return

}

$Results | Format-Table