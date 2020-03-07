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

$nvd_cpe_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
$nvd_cpe_filepath = "$env:TEMP\official-cpe-dictionary_v2.3.xml"

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
foreach ($item in ($xml.'cpe-list'.'cpe-item')[0..1000]) {
    $item.name -match "cpe\:/a:([^\:]+):([^\:]+):([^\:]+)" | Out-Null
    if ($matches) { 
        $vendor = $matches[1]
        $product = $matches[2]
        $version = $matches[3]    
    } else { $vendor = "failed" ; $product = "failed" ; $version = "failed" }

    $vendormatch = $false ; $productmatch = $false ; $versionmatch = $false
    if ($title -match $vendor) { $vendormatch = $true}
    if ($title -match $product) { $productmatch = $true}
    if ($title -match $version) { $versionmatch = $true}        

    $Record = @{
        name =  $item.name
        vendor = $vendor
        product = $product
        version = $version     
        title = ($item.title | ?{$_.lang -eq 'en-US'}).'#text'
    }

    # really just looking to point out differences in cpe name vs. cpe title
    if ($vendormatch -eq $false -or $productmatch -eq $false -or $versionmatch -eq $false) {
        $Records += New-Object -TypeName PSObject -Property $Record
    }


} 

$records | Select-Object -Property name, title, vendor, product, version | Sort-Object -Property name | Out-GridView
