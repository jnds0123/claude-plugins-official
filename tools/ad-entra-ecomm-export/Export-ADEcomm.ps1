<#
.SYNOPSIS
    Exports every mail-enabled object, distribution group and security group from
    on-premises Active Directory, and flags everything matching an "ecomm" pattern.

.DESCRIPTION
    Produces two tiers of output:
      1. Full inventory  - all users, groups and contacts with their addresses.
      2. Ecomm subset    - the same objects filtered to those matching -EcommPattern
                           in any name, address, description, department or OU path,
                           plus expanded membership for every matching group.

    Read-only. Nothing in this script writes to the directory.

.PARAMETER Server
    Domain controller or domain to query. Defaults to the logon domain.

.PARAMETER SearchBase
    Optional DN to scope the search, e.g. "OU=Corp,DC=contoso,DC=com".

.PARAMETER Credential
    Optional alternate credentials.

.PARAMETER EcommPattern
    Regex used for the ecomm filter. Default matches ecomm, e-comm, e_comm, ecom,
    ecomms and ecommerce in any casing, including inside names like GRP_Ecomm_Team
    and MyEcommTeam. It deliberately does NOT match telecom, intercom, datacom or
    addresses at domains such as adobe.com / apple.com / nike.com.

.PARAMETER OutputPath
    Directory for the CSV output. Created if missing.

.EXAMPLE
    .\Export-ADEcomm.ps1 -OutputPath C:\Exports\ecomm

.EXAMPLE
    .\Export-ADEcomm.ps1 -Server dc01.contoso.com -SearchBase "DC=contoso,DC=com" -Verbose
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$EcommPattern = '(?-i)(?:(?<![A-Za-z])[Ee]|(?<=[a-z])E)[\s_-]?(?i:comm?(?:erce)?s?)(?=[^a-z]|$)',
    [string]$OutputPath = (Join-Path (Get-Location) 'ecomm-export-ad')
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------- common args
# $adArgs is for -Filter based searches (accepts SearchBase).
$adArgs = @{}
if ($Server)     { $adArgs['Server']     = $Server }
if ($SearchBase) { $adArgs['SearchBase'] = $SearchBase }
if ($Credential) { $adArgs['Credential'] = $Credential }

# $adConn is for -Identity based lookups, which reject -SearchBase.
$adConn = @{}
if ($Server)     { $adConn['Server']     = $Server }
if ($Credential) { $adConn['Credential'] = $Credential }

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan

# ---------------------------------------------------------------- helpers
function Test-EcommMatch {
    <# Returns $true if any of the named fields matches the ecomm pattern. #>
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)] [string[]]$Fields,
        [Parameter(Mandatory)] [string]$Pattern
    )
    foreach ($field in $Fields) {
        $value = $InputObject.$field
        if ($null -eq $value) { continue }
        foreach ($item in @($value)) {
            if ([string]$item -match $Pattern) { return $true }
        }
    }
    return $false
}

function Get-ADObjectSafe {
    <#
        Runs an AD cmdlet with an extended property list, falling back to a core
        list when the forest schema lacks the Exchange attributes.
    #>
    param(
        [Parameter(Mandatory)] [scriptblock]$Query,
        [Parameter(Mandatory)] [string[]]$ExtendedProperties,
        [Parameter(Mandatory)] [string[]]$CoreProperties
    )
    try {
        return & $Query $ExtendedProperties
    }
    catch {
        Write-Warning "Extended attribute query failed ($($_.Exception.Message.Trim())). Retrying with core attributes only."
        return & $Query $CoreProperties
    }
}

function Expand-ProxyAddress {
    <# Turns a proxyAddresses entry into a typed object. #>
    param([string]$Raw)

    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }

    $prefix  = ''
    $address = $Raw
    if ($Raw -match '^(?<p>[^:]+):(?<a>.*)$') {
        $prefix  = $Matches['p']
        $address = $Matches['a']
    }

    # Case is significant: upper-case SMTP marks the primary address, lower-case an
    # alias. Comparisons must be case-sensitive (-ceq), since PowerShell's default
    # string and switch -Regex comparisons are not.
    $type = if ($prefix -ceq 'SMTP')             { 'Primary SMTP' }
            elseif ($prefix -ceq 'smtp')         { 'Alias SMTP' }
            elseif ($prefix -match '(?i)^x500$') { 'X500' }
            elseif ($prefix -match '(?i)^sip$')  { 'SIP' }
            elseif ($prefix)                     { $prefix }
            else                                 { 'Unqualified' }

    [pscustomobject]@{
        AddressType = $type
        Address     = $address
        Raw         = $Raw
    }
}

# ---------------------------------------------------------------- users
Write-Host 'Querying users...' -ForegroundColor Cyan

$userExtended = @(
    'displayName','mail','proxyAddresses','userPrincipalName','department',
    'title','company','description','enabled','distinguishedName','whenCreated',
    'lastLogonTimestamp','targetAddress','msExchRecipientTypeDetails','msExchHideFromAddressLists'
)
$userCore = @(
    'displayName','mail','proxyAddresses','userPrincipalName','department',
    'title','company','description','enabled','distinguishedName','whenCreated',
    'lastLogonTimestamp'
)

$users = Get-ADObjectSafe -ExtendedProperties $userExtended -CoreProperties $userCore -Query {
    param($props)
    Get-ADUser -Filter * -Properties $props @adArgs
}

$userRecords = foreach ($u in $users) {
    [pscustomobject]@{
        ObjectType         = 'User'
        Name               = $u.Name
        DisplayName        = $u.displayName
        SamAccountName     = $u.SamAccountName
        UserPrincipalName  = $u.UserPrincipalName
        PrimaryEmail       = $u.mail
        ProxyAddresses     = ($u.proxyAddresses -join ';')
        Department         = $u.department
        Title              = $u.title
        Company            = $u.company
        Description        = $u.description
        Enabled            = $u.Enabled
        MailboxType        = $u.msExchRecipientTypeDetails
        HiddenFromGAL      = $u.msExchHideFromAddressLists
        TargetAddress      = $u.targetAddress
        OU                 = ($u.distinguishedName -replace '^CN=.*?(?<!\\),','')
        DistinguishedName  = $u.distinguishedName
        WhenCreated        = $u.whenCreated
        EcommMatch         = (Test-EcommMatch -InputObject $u -Pattern $EcommPattern -Fields @(
                                'Name','displayName','SamAccountName','UserPrincipalName','mail',
                                'proxyAddresses','department','title','company','description','distinguishedName'))
    }
}

# ---------------------------------------------------------------- groups
Write-Host 'Querying groups...' -ForegroundColor Cyan

$groupExtended = @(
    'displayName','mail','proxyAddresses','description','info','managedBy',
    'groupCategory','groupScope','member','memberOf','distinguishedName','whenCreated',
    'msExchRecipientTypeDetails','msExchHideFromAddressLists'
)
$groupCore = @(
    'displayName','mail','proxyAddresses','description','info','managedBy',
    'groupCategory','groupScope','member','memberOf','distinguishedName','whenCreated'
)

$groups = Get-ADObjectSafe -ExtendedProperties $groupExtended -CoreProperties $groupCore -Query {
    param($props)
    Get-ADGroup -Filter * -Properties $props @adArgs
}

$groupRecords = foreach ($g in $groups) {

    # Distribution vs security, and whether a security group is also mail-enabled.
    $isMailEnabled = -not [string]::IsNullOrWhiteSpace($g.mail) -or ($g.proxyAddresses -and $g.proxyAddresses.Count -gt 0)
    $groupType = if ($g.GroupCategory -eq 'Distribution') {
        'Distribution Group'
    }
    elseif ($isMailEnabled) {
        'Mail-Enabled Security Group'
    }
    else {
        'Security Group'
    }

    [pscustomobject]@{
        ObjectType         = 'Group'
        GroupType          = $groupType
        GroupCategory      = [string]$g.GroupCategory
        GroupScope         = [string]$g.GroupScope
        Name               = $g.Name
        DisplayName        = $g.displayName
        SamAccountName     = $g.SamAccountName
        PrimaryEmail       = $g.mail
        ProxyAddresses     = ($g.proxyAddresses -join ';')
        MailEnabled        = $isMailEnabled
        Description        = $g.description
        Notes              = $g.info
        ManagedBy          = $g.managedBy
        MemberCount        = @($g.member).Count
        HiddenFromGAL      = $g.msExchHideFromAddressLists
        OU                 = ($g.distinguishedName -replace '^CN=.*?(?<!\\),','')
        DistinguishedName  = $g.distinguishedName
        WhenCreated        = $g.whenCreated
        EcommMatch         = (Test-EcommMatch -InputObject $g -Pattern $EcommPattern -Fields @(
                                'Name','displayName','SamAccountName','mail','proxyAddresses',
                                'description','info','distinguishedName'))
    }
}

# ---------------------------------------------------------------- contacts
Write-Host 'Querying mail contacts...' -ForegroundColor Cyan

$contacts = @()
try {
    $contacts = Get-ADObject -LDAPFilter '(objectClass=contact)' `
        -Properties displayName,name,mail,proxyAddresses,description,targetAddress,distinguishedName,whenCreated `
        @adArgs
}
catch {
    Write-Warning "Contact query failed: $($_.Exception.Message.Trim())"
}

$contactRecords = foreach ($c in $contacts) {
    [pscustomobject]@{
        ObjectType        = 'Contact'
        Name              = $c.Name
        DisplayName       = $c.displayName
        PrimaryEmail      = $c.mail
        ProxyAddresses    = ($c.proxyAddresses -join ';')
        TargetAddress     = $c.targetAddress
        Description       = $c.description
        OU                = ($c.distinguishedName -replace '^CN=.*?(?<!\\),','')
        DistinguishedName = $c.distinguishedName
        WhenCreated       = $c.whenCreated
        EcommMatch        = (Test-EcommMatch -InputObject $c -Pattern $EcommPattern -Fields @(
                                'Name','displayName','mail','proxyAddresses','description',
                                'targetAddress','distinguishedName'))
    }
}

# ---------------------------------------------------------------- flattened addresses
Write-Host 'Flattening address list...' -ForegroundColor Cyan

$addressRecords = New-Object System.Collections.Generic.List[object]

function Add-AddressRows {
    param($Record, [string]$ObjectKind)

    $emitted = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)

    $emit = {
        param([string]$Type, [string]$Address)
        if ([string]::IsNullOrWhiteSpace($Address)) { return }
        if (-not $emitted.Add($Address)) { return }
        $addressRecords.Add([pscustomobject]@{
            Source            = 'AD'
            ObjectKind        = $ObjectKind
            ObjectName        = $Record.Name
            DisplayName       = $Record.DisplayName
            SamAccountName    = $Record.SamAccountName
            AddressType       = $Type
            Address           = $Address
            DistinguishedName = $Record.DistinguishedName
            EcommMatch        = $Record.EcommMatch
        })
    }

    # proxyAddresses first: they carry the authoritative primary/alias marker.
    foreach ($raw in ($Record.ProxyAddresses -split ';')) {
        $parsed = Expand-ProxyAddress -Raw $raw
        if (-not $parsed) { continue }
        & $emit $parsed.AddressType $parsed.Address
    }

    # mail attribute only if it was not already covered by a proxy address.
    & $emit 'mail attribute' $Record.PrimaryEmail
}

foreach ($r in $userRecords)    { Add-AddressRows -Record $r -ObjectKind 'User' }
foreach ($r in $groupRecords)   { Add-AddressRows -Record $r -ObjectKind $r.GroupType }
foreach ($r in $contactRecords) { Add-AddressRows -Record ($r | Select-Object *, @{n='SamAccountName';e={$null}}) -ObjectKind 'Contact' }

# ---------------------------------------------------------------- ecomm group membership
Write-Host 'Expanding membership of ecomm groups...' -ForegroundColor Cyan

$ecommGroups  = @($groupRecords | Where-Object EcommMatch)
$memberRecords = New-Object System.Collections.Generic.List[object]

foreach ($g in $ecommGroups) {
    $members = @()
    try {
        $members = Get-ADGroupMember -Identity $g.DistinguishedName -Recursive @adConn
    }
    catch {
        Write-Warning "Could not expand '$($g.Name)': $($_.Exception.Message.Trim())"
        continue
    }

    foreach ($m in $members) {
        $mail = $null
        try {
            $mail = (Get-ADObject -Identity $m.distinguishedName -Properties mail @adConn).mail
        }
        catch { }

        $memberRecords.Add([pscustomobject]@{
            GroupName         = $g.Name
            GroupType         = $g.GroupType
            GroupEmail        = $g.PrimaryEmail
            GroupDN           = $g.DistinguishedName
            MemberName        = $m.Name
            MemberSam         = $m.SamAccountName
            MemberClass       = $m.objectClass
            MemberEmail       = $mail
            MemberDN          = $m.distinguishedName
        })
    }
}

# ---------------------------------------------------------------- write output
function Write-Csv {
    param($Data, [string]$FileName)
    $path = Join-Path $OutputPath $FileName
    if ($Data -and @($Data).Count -gt 0) {
        @($Data) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    else {
        Set-Content -Path $path -Value '' -Encoding UTF8
    }
    Write-Host ("  {0,-40} {1,6} rows" -f $FileName, @($Data).Count)
}

Write-Host 'Writing CSV files...' -ForegroundColor Cyan

Write-Csv $userRecords                                        'ad_users_all.csv'
Write-Csv $groupRecords                                       'ad_groups_all.csv'
Write-Csv ($groupRecords | Where-Object GroupType -eq 'Distribution Group')          'ad_groups_distribution.csv'
Write-Csv ($groupRecords | Where-Object GroupType -eq 'Security Group')              'ad_groups_security.csv'
Write-Csv ($groupRecords | Where-Object GroupType -eq 'Mail-Enabled Security Group') 'ad_groups_mail_enabled_security.csv'
Write-Csv $contactRecords                                     'ad_contacts_all.csv'
Write-Csv $addressRecords                                     'ad_addresses_all.csv'

Write-Csv ($userRecords    | Where-Object EcommMatch)         'ad_ecomm_users.csv'
Write-Csv ($groupRecords   | Where-Object EcommMatch)         'ad_ecomm_groups.csv'
Write-Csv ($contactRecords | Where-Object EcommMatch)         'ad_ecomm_contacts.csv'
Write-Csv ($addressRecords | Where-Object EcommMatch)         'ad_ecomm_addresses.csv'
Write-Csv $memberRecords                                      'ad_ecomm_group_members.csv'

# ---------------------------------------------------------------- summary
Write-Host ''
Write-Host '================ AD SUMMARY ================' -ForegroundColor Green
Write-Host ("Users                        : {0}" -f @($userRecords).Count)
Write-Host ("Groups (all)                 : {0}" -f @($groupRecords).Count)
Write-Host ("  Distribution groups        : {0}" -f @($groupRecords | Where-Object GroupType -eq 'Distribution Group').Count)
Write-Host ("  Security groups            : {0}" -f @($groupRecords | Where-Object GroupType -eq 'Security Group').Count)
Write-Host ("  Mail-enabled security      : {0}" -f @($groupRecords | Where-Object GroupType -eq 'Mail-Enabled Security Group').Count)
Write-Host ("Contacts                     : {0}" -f @($contactRecords).Count)
Write-Host ("Distinct address rows        : {0}" -f $addressRecords.Count)
Write-Host '--------------- ECOMM MATCHES --------------' -ForegroundColor Yellow
Write-Host ("Pattern                      : {0}" -f $EcommPattern)
Write-Host ("Ecomm users                  : {0}" -f @($userRecords    | Where-Object EcommMatch).Count)
Write-Host ("Ecomm groups                 : {0}" -f $ecommGroups.Count)
Write-Host ("Ecomm contacts               : {0}" -f @($contactRecords | Where-Object EcommMatch).Count)
Write-Host ("Ecomm address rows           : {0}" -f @($addressRecords | Where-Object EcommMatch).Count)
Write-Host ("Ecomm group member rows      : {0}" -f $memberRecords.Count)
Write-Host '============================================' -ForegroundColor Green
