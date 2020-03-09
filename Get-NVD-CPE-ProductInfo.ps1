$nvd_feed_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
$nvd_feed_filepath = "$env:TEMP\official-cpe-dictionary_v2.3.xml"
$nvd_feed_filepath_csv = "$env:TEMP\official-cpe-dictionary_v2.3.csv"
$page_limit = 10000

function Get-Web-Download($url)
{

    # obtain download location
    $download_filename = $url.Split("/")[-1]
    $download_path = "$env:temp\$download_filename"

    # remove any previously downloaded fies
    if (test-path $download_path) {
        Remove-Item -Path $download_path -Force
    }

    # download the file
    $client = new-object System.Net.WebClient 
    $client.DownloadFile($url, $download_path) 

    # return the path to file
    return $download_path
}

function Expand-ZIPFile($file, $destination)
{
    $shell = new-object -com shell.application
    $zip = $shell.NameSpace($file)
    foreach($item in $zip.items())
    {
        $shell.Namespace($destination).copyhere($item)
    }
}

# take note of start date-time
$jobstart = Get-Date

# remove previons version of output csv file
if (Test-Path -Path $nvd_feed_filepath_csv) { 
    Remove-Item -path $nvd_feed_filepath_csv -Force
}

# remove previous version of downloads
if (test-path $nvd_feed_filepath) {
    Remove-Item $nvd_feed_filepath -Force
}

# download most recent zip CVE list
Write-host "$(get-date) - Downloading $($nvd_feed_url)."
$download_path = Get-Web-Download -url $nvd_feed_url

# extract the zipped CVE list
Write-host "$(get-date) - Expanding $($download_path)."
Expand-ZIPFile -file $download_path -destination $env:TEMP

# read entries into an xml
Write-host "$(get-date) - Reading $($nvd_feed_filepath) into xml object"
$xml = New-Object -TypeName XML
$xml.Load($nvd_feed_filepath)

# convert xml entries of interest into csv
Write-host "$(get-date) - Convert xml entries of interest to CSV"
$record_count = 0
$page_size = 0
$page_count = 0
$records = @()

# loop through each cpe-item and append properties of interst to object
foreach ($item in ($xml.'cpe-list'.'cpe-item')[0..2000]) {   # remove slicing when not testing

    # increment counter of items observed
    $record_count++
    $page_size++

    # extract vendor, product, and version from name field (better, but not best, for humans)
    $item.'cpe23-item'.name -match "cpe\:2\.3\:a:([^\:]+):([^\:]+):([^\:]+)"  | Out-Null
    if ($matches) { 
        $vendor = $matches[1]
        $product = $matches[2]
        $version = $matches[3]    
    } else { $vendor = "extract_failed" ; $product = "extract_failed" ; $version = "extract_failed" }

    # extract the url of of some of the more common references (change log, version)
    $references = @($item.references.ChildNodes)
    $changelog_href = ($references | where-object{$_.'#text' -eq "Change Log"}).href | Select-Object -First 1  
    $version_href = ($references | where-object{$_.'#text' -eq "Version"}).href | Select-Object -First 1

    # tee up a hash table of properties of interest
    $Record = @{
        name =  $item.name
        cpe23item_name = $item.'cpe23-item'.name
        vendor = $vendor
        product = $product
        version = $version
        changelog_url = $changelog_href
        version_url = $version_href               
        title = ($item.title | where-object{$_.lang -eq 'en-US'}).'#text'
    }

    # append records array with hash table members
    $Records += New-Object -TypeName PSObject -Property $Record

    # now, if we are at N items, lets page out to CSV files
    if ($page_size -eq $page_limit) { 
            $page_count++
            $page_size = 0
            write-host "$(get-date) - Appending results file $($nvd_feed_filepath_csv) with $($page_limit) processed records. `[Page $($page_count)`]."
            $records | Export-Csv -Path $nvd_feed_filepath_csv -NoTypeInformation -Append
            # reset the records object
            $records = @() 
    }
} 

# now that we are done with the loop, append remaining content to CSV file
if ($records.count -ge 1) {  
    write-host "$(get-date) - Appending results file $($nvd_feed_filepath_csv) with remaining $($page_size) records."
    $records | Export-Csv -Path $nvd_feed_filepath_csv -NoTypeInformation -Append
}

# give back that memory
$xml | Out-Null

# write summary of time to execute
$jobTotalSeconds = (New-TimeSpan -Start $jobstart).TotalSeconds

write-host "$(get-date) - Task completed in $($jobTotalSeconds) seconds converting $($record_count) records!"


<#
###################################
# INTERACTIVE STUFF FOR DISCOVERY #
###################################

# read stored records into powershell PSCustomObject
$Records = Import-Csv -Path $nvd_feed_filepath_csv

# show records 
$records | Select-Object -Property name, cpe23item_name, title, vendor, product, version, changelog_url, version_url

# show records in gridview
$records | Select-Object -Property name, cpe23item_name, title, vendor, product, version, changelog_url, version_url | out-GridView    

#>
