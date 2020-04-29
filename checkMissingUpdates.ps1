
#Using WUA to Scan for Updates Offline with PowerShell  
#VBS version: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/aa387290(v=vs.85)  

<#
$DebugPreference = "Continue"           # Debug Mode
$DebugPreference = "SilentlyContinue"   # Normal Mode
#>


# make sure cab file path is present
$CabFilePath = "c:\apps\wsusscn2.cab"
if (!(Test-Path -Path $CabFilePath)) {
    $Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
	[void]$Output.Add($Date)
	[void]$Output.add("Error=`"Cabinet File Not Found in Path: $($CabFilePath)`"")
    return $null  

}

# get age of cab file
$LastWriteTime = Get-ChildItem -Path $CabFilePath | Select-object -ExpandProperty LastWriteTime
$CabFileAgeDays = [math]::round((New-TimeSpan -Start $LastWriteTime).TotalDays,0)

  
$UpdateSession = New-Object -ComObject Microsoft.Update.Session  
$UpdateServiceManager  = New-Object -ComObject Microsoft.Update.ServiceManager  
$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $CabFilePath , 1)  
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()   
  
Write-Debug "Searching for missing windows updates according to $($CabFilePath), which is $($CabFileAgeDays) days old."
  
$UpdateSearcher.ServerSelection = 3 #ssOthers 
 
$UpdateSearcher.IncludePotentiallySupersededUpdates = $true # good for older OSes, to include Security-Only or superseded updates in the result list, otherwise these are pruned out and not returned as part of the final result list 
  
$UpdateSearcher.ServiceID = $UpdateService.ServiceID.ToString()  
  
$SearchResult = $UpdateSearcher.Search("IsInstalled=0") # or "IsInstalled=0 or IsInstalled=1" to also list the installed updates as MBSA did  
  
$Updates = $SearchResult.Updates  
 
if($Updates.Count -eq 0){  
    $Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
	[void]$Output.Add($Date)
	[void]$Output.add("Title=`"$($update.Title)`"")
    return $null  
}  

write-host "4"
foreach($Update in $Updates){   

    # prepare a string of key-value pairs for splunk to extract nicely
	$Output = New-Object System.Collections.ArrayList

    $Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
	[void]$Output.Add($Date)

	[void]$Output.add("Title=`"$($update.Title)`"")
	[void]$Output.add("MsrcSeverity=`"$($update.MsrcSeverity)`"")
	[void]$Output.add("KBArticleIDs=`"$($update.KBArticleIDs)`"")
	[void]$Output.add("RebootRequired=`"$($update.RebootRequired)`"")
	[void]$Output.add("SecurityBulletinIDs=`"$($update.SecurityBulletinIDs)`"")
	[void]$Output.add("Description=`"$($update.Description)`"")
	
    # print output for input of splunk script-based input handler to catch
	Write-Host ($Output -join " ")

}
