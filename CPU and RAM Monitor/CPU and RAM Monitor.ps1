$Servers = @("")

$Output = @()
$History = @()

$Gap = "     "
$host.ui.RawUI.WindowTitle = "CPU and RAM Monitor"

do {
    foreach ($Server in $Servers) {
        $TempResults = Invoke-Command -ComputerName $Server -ScriptBlock {

            $totalRam = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum
            $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $cpuTime = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
            $availMem = (Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
            $Return = [PSCustomObject]@{
                DeviceName  = $ENV:ComputerName
                Date        = $date
                CPU         = $cpuTime.ToString("#,00.0")
                RAM         = $availMem.ToString("N0")
                RAMPercent  = (104857600 * $availMem / $totalRam).ToString("#,00.0")
                PreviousCPU = ""
            }
            Write-Output -InputObject $Return
        }

        if ($Output.DeviceName -contains $TempResults.DeviceName) {
            ($Output | Where-Object { $_.DeviceName -eq $TempResults.DeviceName }).PreviousCPU = ($Output | Where-Object { $_.DeviceName -eq $TempResults.DeviceName }).CPU
            ($Output | Where-Object { $_.DeviceName -eq $TempResults.DeviceName }).Date = $TempResults.Date
            ($Output | Where-Object { $_.DeviceName -eq $TempResults.DeviceName }).CPU = $TempResults.CPU
            ($Output | Where-Object { $_.DeviceName -eq $TempResults.DeviceName }).RAM = $TempResults.RAM
            ($Output | Where-Object { $_.DeviceName -eq $TempResults.DeviceName }).RAMPercent = $TempResults.RAMPercent
        } else {
            $Output += $TempResults
        }

        Clear-Host

        $Header1 = "Device Name       Date                   CPU      Prev     RAM      RAM Percent"
        $Header2 = ""
        if ($Header2.Length -lt $Header1.Length) {
            do {
                $Header2 = "$Header2-"
            } while (
                $Header2.Length -lt $Header1.Length
            )
        }

        Write-Host $Header1
        Write-Host $Header2
        foreach ($currentItemName in $Output) {
            if ($($currentItemName.DeviceName) -eq $Server.Replace(".t01.euc.sa.gov.au", "")) {
                Write-Host "$($currentItemName.DeviceName)" -ForegroundColor Green -NoNewline
            } else {
                Write-Host "$($currentItemName.DeviceName)" -NoNewline
            }

            Write-Host "$Gap$($currentItemName.Date)$Gap" -NoNewline
            if ($currentItemName.CPU -ge 80) {
                Write-Host $currentItemName.CPU -NoNewline -ForegroundColor Red
            } else {
                Write-Host $currentItemName.CPU -NoNewline
            }
            Write-Host $Gap -NoNewline
            if ($currentItemName.PreviousCPU -ge 80) {
                Write-Host $currentItemName.PreviousCPU -NoNewline -ForegroundColor Red
            } else {
                Write-Host $currentItemName.PreviousCPU -NoNewline
            }

            Write-Host "$Gap$($currentItemName.RAM)$Gap$($currentItemName.RAMPercent)"
        }

    }
} until (
    $stop -eq $true
)
