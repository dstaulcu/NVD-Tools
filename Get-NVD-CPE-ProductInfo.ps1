
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
    write-host "Downloading $url" 
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

$nvd_cpe_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
$nvd_cpe_filepath = "$env:TEMP\official-cpe-dictionary_v2.3.xml"
$nvd_cpe_filepath_csv = "$env:TEMP\official-cpe-dictionary_v2.3.csv"

# remove previons version of output csv file
if (Test-Path -Path $nvd_cpe_filepath_csv) { 
    Remove-Item -path $nvd_cpe_filepath_csv -Force
}

# remove previous version of downloads
if (test-path $nvd_cpe_filepath) {
    Remove-Item $nvd_cpe_filepath -Force
}

# download most recent zip CVE list
$download_path = Get-Web-Download -url $nvd_cpe_url

# extract the zipped CVE list
Write-host "Expanding $download_path."
Expand-ZIPFile -file $download_path -destination $env:TEMP

# read entries into an array
Write-host "Reading $nvd_cpe_filepath into entries array"

# load it into an XML object:
$xml = New-Object -TypeName XML
$xml.Load($nvd_cpe_filepath)

$records = @()
$counter = 0
$pages = 0

# loop through each cpe-item and append properties of interst to object
foreach ($item in ($xml.'cpe-list'.'cpe-item')) {

    # increment counter of items observed
    $counter++

    # extract vendor, product, and version from name field (better, but not best, for humans)
    $item.name -match "cpe\:/a:([^\:]+):([^\:]+):([^\:]+)" | Out-Null
    if ($matches) { 
        $vendor = $matches[1]
        $product = $matches[2]
        $version = $matches[3]    
    } else { $vendor = "extract_failed" ; $product = "extract_failed" ; $version = "extract_failed" }

    # tee up a hash table of properties of interest
    $Record = @{
        name =  $item.name
        vendor = $vendor
        product = $product
        version = $version     
        title = ($item.title | where-object{$_.lang -eq 'en-US'}).'#text'
    }

    # append records array with hash table members
    $Records += New-Object -TypeName PSObject -Property $Record

    # now, if we are at 1000 items, lets page out to CSV files
    if ($counter -eq 10000) { 
            $pages++
            $counter = 0
            write-host "$(get-date) - Appending results file $($nvd_cpe_filepath_csv) with 10K processed records. `[Page $($pages)`]."
            $records | Export-Csv -Path $nvd_cpe_filepath_csv -NoTypeInformation -Append
            # reset the records object
            $records = @() 
    }
} 

# now that we are done with the loop, append remaining content to CSV file
write-host "$(get-date) - Appending results file $($nvd_cpe_filepath_csv) with remaining $($counter) records."
$records | Export-Csv -Path $nvd_cpe_filepath_csv -NoTypeInformation -Append

# give back that memory
$xml | Out-Null

# prepare results for interaction
$Records = Import-Csv -Path $nvd_cpe_filepath_csv

# write summary of time to execute
$jobTotalSeconds = (New-TimeSpan -Start $jobstart).TotalSeconds

write-host "Task completed in $($jobTotalSeconds) seconds producting $($records.count) records!"

<#
$records | Select-Object -Property name, title, vendor, product, version | out-GridView    
$Records = Import-Csv -Path $nvd_cpe_filepath_csv
$records | ?{$_.name -match "[^~]~$"} | Select-Object -Property name, title, vendor, product, version | out-GridView    
$records | Select-Object -Property name, title, vendor, product, version | Sort-Object -Property name | Out-GridView
#>
