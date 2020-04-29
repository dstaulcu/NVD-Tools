
<#
https://docs.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline

http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab
#>


$Transfers = @()

$Transfer = @{
    Source = "http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab"
    Destination = "c:\apps\wsusscn2.cab"
}

$Transfers += New-Object -TypeName PSObject -Property $Transfer



$Transfers | Start-BitsTransfer