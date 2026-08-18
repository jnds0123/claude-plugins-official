<#
.SYNOPSIS
    Merges the AD and Entra exports into one deduplicated address list and a
    consolidated ecomm report.

.DESCRIPTION
    Reads *_addresses_all.csv from one or more export folders and produces:
      - all_addresses_merged.csv  every address, one row per address per source
      - all_addresses_unique.csv  one row per address, with the sources that hold it
      - ecomm_master.csv          the ecomm subset of the unique list
      - ecomm_orphans.csv         addresses present in only one directory, which is
                                  usually what you want to look at during a cleanup

.EXAMPLE
    .\Merge-EcommReport.ps1 -ExportPath .\ecomm-export-ad,.\ecomm-export-entra -OutputPath .\ecomm-merged
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]]$ExportPath,
    [string]$OutputPath = (Join-Path (Get-Location) 'ecomm-merged')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$rows = New-Object System.Collections.Generic.List[object]

foreach ($folder in $ExportPath) {
    if (-not (Test-Path $folder)) {
        Write-Warning "Export folder not found, skipping: $folder"
        continue
    }
    $files = Get-ChildItem -Path $folder -Filter '*addresses_all.csv' -File
    foreach ($file in $files) {
        $data = @(Import-Csv -Path $file.FullName)
        Write-Host ("Loaded {0,6} rows from {1}" -f $data.Count, $file.Name)
        foreach ($d in $data) {
            $rows.Add([pscustomobject]@{
                Source      = $d.Source
                ObjectKind  = $d.ObjectKind
                ObjectName  = if ($d.PSObject.Properties['ObjectName']) { $d.ObjectName } else { $d.DisplayName }
                Identifier  = if ($d.PSObject.Properties['SamAccountName']) { $d.SamAccountName } else { $d.UPNorAlias }
                AddressType = $d.AddressType
                Address     = ($d.Address).Trim()
                EcommMatch  = ('True' -eq "$($d.EcommMatch)")
            })
        }
    }
}

if ($rows.Count -eq 0) { throw "No address rows found in: $($ExportPath -join ', ')" }

$merged = $rows | Sort-Object Address, Source

$unique = $merged |
    Where-Object { $_.Address } |
    Group-Object -Property { $_.Address.ToLowerInvariant() } |
    ForEach-Object {
        $group   = $_.Group
        $sources = @($group.Source | Sort-Object -Unique)
        [pscustomobject]@{
            Address      = $group[0].Address
            Sources      = ($sources -join ';')
            SourceCount  = $sources.Count
            InAD         = [bool](@($sources) -contains 'AD')
            InCloud      = [bool](@($sources | Where-Object { $_ -ne 'AD' }).Count -gt 0)
            ObjectKinds  = ((@($group.ObjectKind | Sort-Object -Unique)) -join ';')
            ObjectNames  = ((@($group.ObjectName | Where-Object { $_ } | Sort-Object -Unique)) -join ';')
            AddressTypes = ((@($group.AddressType | Sort-Object -Unique)) -join ';')
            EcommMatch   = [bool](@($group | Where-Object EcommMatch).Count -gt 0)
        }
    } | Sort-Object Address

$merged | Export-Csv (Join-Path $OutputPath 'all_addresses_merged.csv') -NoTypeInformation -Encoding UTF8
$unique | Export-Csv (Join-Path $OutputPath 'all_addresses_unique.csv') -NoTypeInformation -Encoding UTF8
($unique | Where-Object EcommMatch) | Export-Csv (Join-Path $OutputPath 'ecomm_master.csv') -NoTypeInformation -Encoding UTF8
($unique | Where-Object { $_.SourceCount -eq 1 }) | Export-Csv (Join-Path $OutputPath 'ecomm_orphans.csv') -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host '=============== MERGED SUMMARY =============' -ForegroundColor Green
Write-Host ("Address rows across sources  : {0}" -f @($merged).Count)
Write-Host ("Unique addresses             : {0}" -f @($unique).Count)
Write-Host ("  Present in AD only         : {0}" -f @($unique | Where-Object { $_.InAD -and -not $_.InCloud }).Count)
Write-Host ("  Present in cloud only      : {0}" -f @($unique | Where-Object { $_.InCloud -and -not $_.InAD }).Count)
Write-Host ("  Present in both            : {0}" -f @($unique | Where-Object { $_.InAD -and $_.InCloud }).Count)
Write-Host ("Ecomm addresses              : {0}" -f @($unique | Where-Object EcommMatch).Count)
Write-Host '============================================' -ForegroundColor Green
Write-Host "Output: $OutputPath"
