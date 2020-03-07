function Get-NVD-CVE-Entries($nvdcve_filepath)
{

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
       
    # make dummy root to force creation
    $nvdxml=[xml]'<root/>'

    # load the recent findings
    # online version
    # $nvdxml.load('http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-recent.xml')
       
    # local version
    $nvdxml.load($nvdcve_filepath)

    # intialize namespace manager
    $nsmgr = New-Object System.XML.XmlNamespaceManager($nvdxml.NameTable)     
     
    # add a default namespace to reference things that are explicit
    $nsmgr.AddNamespace('default','http://scap.nist.gov/schema/feed/vulnerability/2.0')
         
    # add additional namespaces for reference
    $nsmgr.AddNamespace('xsi','http://www.w3.org/2001/XMLSchema-instance')
    $nsmgr.AddNamespace('vuln','http://scap.nist.gov/schema/vulnerability/0.4')
    $nsmgr.AddNamespace('cvss','http://scap.nist.gov/schema/cvss-v2/0.2')

    # create Namespace hashtable
    $nameHash = @{xsi="http://www.w3.org/2001/XMLSchema-instance"; vuln="http://scap.nist.gov/schema/vulnerability/0.4"; cvss="http://scap.nist.gov/schema/cvss-v2/0.2"}

    # select the nodes you need here
    $entries = $nvdxml.SelectNodes('//default:entry',$nsmgr)

    return $entries
    
}

function Get-NVD-CPE-Entries($nvdcpe_filepath)
{
       
   # make dummy root to force creation
    $nvdxml=[xml]'<root/>'
    
    # local version
    $nvdxml.load($nvdcve_filepath)

    # intialize namespace manager
    $nsmgr = New-Object System.XML.XmlNamespaceManager($nvdxml.NameTable)     
     
    # add a default namespace to reference things that are explicit
    $nsmgr.AddNamespace('default','http://scap.nist.gov/schema/feed/vulnerability/2.0')
         
    # add additional namespaces for reference
    $nsmgr.AddNamespace('xsi','http://www.w3.org/2001/XMLSchema-instance')
    $nsmgr.AddNamespace('vuln','http://scap.nist.gov/schema/vulnerability/0.4')
    $nsmgr.AddNamespace('cvss','http://scap.nist.gov/schema/cvss-v2/0.2')

    # create Namespace hashtable
    $nameHash = @{xsi="http://www.w3.org/2001/XMLSchema-instance"; vuln="http://scap.nist.gov/schema/vulnerability/0.4"; cvss="http://scap.nist.gov/schema/cvss-v2/0.2"}

    # select the nodes you need here
    $entries = $nvdxml.SelectNodes('//default:entry',$nsmgr)

    return $entries
    
}

function xmlNodeToPsCustomObject ($node){
    $hash = @{}
    foreach($attribute in $node.attributes){
        $hash.$($attribute.name) = $attribute.Value
    }
    $childNodesList = ($node.childnodes | ?{$_ -ne $null}).LocalName
    foreach($childnode in ($node.childnodes | ?{$_ -ne $null})){
        if(($childNodesList | ?{$_ -eq $childnode.LocalName}).count -gt 1){
            if(!($hash.$($childnode.LocalName))){
                $hash.$($childnode.LocalName) += @()
            }
            if ($childnode.'#text' -ne $null) {
                $hash.$($childnode.LocalName) += $childnode.'#text'
            }
            $hash.$($childnode.LocalName) += xmlNodeToPsCustomObject($childnode)
        }else{
            if ($childnode.'#text' -ne $null) {
                $hash.$($childnode.LocalName) = $childnode.'#text'
            }else{
                $hash.$($childnode.LocalName) = xmlNodeToPsCustomObject($childnode)
            }
        }   
    }
    return $hash | ConvertTo-PsCustomObjectFromHashtable
}

function ConvertTo-PsCustomObjectFromHashtable { 
    param ( 
        [Parameter(  
            Position = 0,   
            Mandatory = $true,   
            ValueFromPipeline = $true,  
            ValueFromPipelineByPropertyName = $true  
        )] [object[]]$hashtable 
    ); 

    begin { $i = 0; } 

    process { 
        foreach ($myHashtable in $hashtable) { 
            if ($myHashtable.GetType().Name -eq 'hashtable') { 
                $output = New-Object -TypeName PsObject; 
                Add-Member -InputObject $output -MemberType ScriptMethod -Name AddNote -Value {  
                    Add-Member -InputObject $this -MemberType NoteProperty -Name $args[0] -Value $args[1]; 
                }; 
                $myHashtable.Keys | Sort-Object | % {  
                    $output.AddNote($_, $myHashtable.$_);  
                } 
                $output
            } else { 
                Write-Warning "Index $i is not of type [hashtable]"; 
            }
            $i += 1;  
        }
    } 
}


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
