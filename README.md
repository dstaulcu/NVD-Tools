# NVD-Tools
Collection of scripts to interact with NVD content

| Script        | Description   |
| :------------- |:-------------|
| Get-NVD-CPE-ProductInfo.ps1 | Downloads most recent CPE. Selects XML entries of interest. Returns name, title, vendor, product, version, and most common reference urls in CSV file in preparation for load into SQL. |
| Get-Microsoft-VulnerabilityRemediations.ps1 | Downloads Microsoft Common Vulnerability Reporting Framework (CVRF) documents and produces list of remdiations, by product, for CVE entries. |
