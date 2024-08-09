if (-not ("TrustAllCertsPolicy" -as [type])) {
    Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
    return true;
}
    }
"@
    $AllProtocols = [System.Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

$DSServers = @("DSLoadBalancer.domain.FQDN",
    "DSServer1.domain.FQDN",
    "DSServer2.domain.FQDN")

$APIServers = @("APILoadBalancer.domain.FQDN",
    "APIServer1.domain.FQDN",
    "APIServer2.domain.FQDN")

$output = @()
foreach ($DSServer in $DSServers) {
    Write-Host "Checking $DSServer Device Services"
    $Response = Invoke-RestMethod -Method Get -Uri "https://$DSServer/deviceservices/awhealth/v1"

    if ($Response.Version -eq "AirWatch*") {
        $UpDownStatus = "Up"
    } else { $UpDownStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $DSServer
        Type     = "Device Services"
        Response = $UpDownStatus
    }

    $output += $TempResponse

    Write-Host "Checking $DSServer Device Management"
    $Response = Invoke-RestMethod -Method Get -Uri "https://$DSServer/devicemanagement/awhealth/v1"

    if ($Response.Version -eq "AirWatch*") {
        $UpDownStatus = "Up"
    } else { $UpDownStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $DSServer
        Type     = "Device Management"
        Response = $UpDownStatus
    }

    $output += $TempResponse

    Write-Host "Checking $DSServer Device Enrollment"
    $EnrollResponse = Invoke-WebRequest -Uri "https://$DSServer/DeviceManagement/enrollment"

    if ($EnrollResponse.StatusCode -eq "200") {
        $EnrollStatus = "Up"
    } else { $EnrollStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $DSServer
        Type     = "Device Enrollment"
        Response = $EnrollStatus
    }

    $output += $TempResponse
}

foreach ($APIServer in $APIServers) {
    Write-Host "Checking $APIServer API MDM"
    $MDMResponse = Invoke-RestMethod -Method Get -Uri "https://$APIServer/api/mdm/hc"

    Write-Host "Checking $APIServer API System"
    $SystemResponse = Invoke-RestMethod -Method Get -Uri "https://$APIServer/api/system/hc"

    Write-Host "Checking $APIServer API MEM"
    $MEMResponse = Invoke-RestMethod -Method Get -Uri "https://$APIServer/api/mem/hc"

    Write-Host "Checking $APIServer API MAM"
    $MAMResponse = Invoke-RestMethod -Method Get -Uri "https://$APIServer/api/mam/hc"

    if ($MDMResponse -like "Hello API*") {
        $APIStatus = "Up"
    } else { $APIStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $APIServer
        Type     = "API MDM"
        Response = $APIStatus
    }

    $output += $TempResponse

    if ($SystemResponse -like "Hello API*") {
        $APIStatus = "Up"
    } else { $APIStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $APIServer
        Type     = "API System"
        Response = $APIStatus
    }

    $output += $TempResponse

    if ($MEMResponse -like "Hello API*") {
        $APIStatus = "Up"
    } else { $APIStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $APIServer
        Type     = "API MEM"
        Response = $APIStatus
    }

    $output += $TempResponse

    if ($MAMResponse -like "Hello API*") {
        $APIStatus = "Up"
    } else { $APIStatus = "Down" }

    $TempResponse = [PSCustomObject]@{
        Server   = $APIServer
        Type     = "API MAM"
        Response = $APIStatus
    }

    $output += $TempResponse

}

$output | Sort-Object -Property Server, Type