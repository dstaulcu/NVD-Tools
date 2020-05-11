
<#
https://www.microsoft.com/en-us/wdsi/defenderupdates

Windows Defender Antivirus for Windows 10 and Windows 8.1 (https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64)

The links point to an executable file named mpam-fe.exe, mpam-feX64.exe, or mpas-fe.exe (used by older antispyware solutions). 
Simply launch the file to manually install the latest security intelligence.

#>

<#
$DebugPreference = "Continue"           # Debug Mode
$DebugPreference = "SilentlyContinue"   # Normal Mode
#>


$DownloadSource = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"
$DownloadLocation = "$($env:TEMP)\mpam-fe.exe"

$Response = Invoke-WebRequest -Uri $DownloadSource -Method Head
if ($Response.StatusCode -ne 200) {
    write-host "there was a problem"
    return($null)
}

# Assume a download needed
$DownloadNeeded = $true

# check to see if client copy exists and is up to date
if (Test-Path -Path $DownloadLocation) {

    # get the date of the client copy      
    $ClientLastWrite = Get-ChildItem -Path $DownloadLocation | Select-Object -ExpandProperty LastWriteTime

    # get the date of the server copy
    $ServerLastWrite = $Response.BaseResponse.LastModified

    # print the respective dates when debug mode enabled
    write-debug "Last write date of client file is: $($ClientLastWrite)."
    write-debug "Last write date of server file is: $($ServerLastWrite )."

    # set DownloadNeeded flag to true if client and server file dates don't match
    if ($ServerLastWrite -eq $ClientLastWrite) { 
        write-debug "client and server file dates matched. download not needed"
        $DownloadNeeded = $false
    } else {
        write-debug "client and server file did not match. download needed"
    }
} else {
    write-debug "client copy of file not present. download needed."
}


if ($DownloadNeeded -eq $True) {
    write-debug "invoking bits download to $($DownloadLocation)."
    Start-BitsTransfer -Source $Response.BaseResponse.ResponseUri.AbsoluteUri -Destination $DownloadLocation
}