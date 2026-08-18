<#
.SYNOPSIS
    Exports every mail-enabled object, distribution list, Microsoft 365 group and
    security group from Entra ID (and optionally Exchange Online), flagging
    everything matching an "ecomm" pattern.

.DESCRIPTION
    Graph covers users and all group flavours. Pure Exchange recipients that do not
    exist as Entra groups - shared mailboxes, mail contacts, mail users and dynamic
    distribution lists - only surface through Exchange Online, so pass
    -IncludeExchangeOnline for full coverage of the mail estate.

    Read-only. Nothing in this script writes to the tenant.

.PARAMETER TenantId
    Optional tenant id or domain to connect to.

.PARAMETER EcommPattern
    Regex used for the ecomm filter. Default matches ecomm, e-comm, e_comm, ecom,
    ecomms and ecommerce in any casing, including inside names like GRP_Ecomm_Team
    and MyEcommTeam. It deliberately does NOT match telecom, intercom, datacom or
    addresses at domains such as adobe.com / apple.com / nike.com.

.PARAMETER IncludeExchangeOnline
    Also query Exchange Online for distribution groups, dynamic distribution
    groups, mail contacts, mail users and shared mailboxes.

.PARAMETER OutputPath
    Directory for the CSV output. Created if missing.

.NOTES
    Modules   : Microsoft.Graph.Authentication, Microsoft.Graph.Users,
                Microsoft.Graph.Groups  (plus ExchangeOnlineManagement when
                -IncludeExchangeOnline is used)
    Graph scopes : User.Read.All, Group.Read.All, GroupMember.Read.All, Directory.Read.All
    Exchange role: View-Only Recipients (Global Reader is sufficient)

.EXAMPLE
    .\Export-EntraEcomm.ps1 -IncludeExchangeOnline -OutputPath C:\Exports\ecomm
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$EcommPattern = '(?-i)(?:(?<![A-Za-z])[Ee]|(?<=[a-z])E)[\s_-]?(?i:comm?(?:erce)?s?)(?=[^a-z]|$)',
    [switch]$IncludeExchangeOnline,
    [string]$OutputPath = (Join-Path (Get-Location) 'ecomm-export-entra')
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- setup
foreach ($module in @('Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Groups')) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Required module '$module' is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    Import-Module $module -ErrorAction Stop
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan

$scopes = @('User.Read.All','Group.Read.All','GroupMember.Read.All','Directory.Read.All')
$connectArgs = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectArgs['TenantId'] = $TenantId }

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
Connect-MgGraph @connectArgs
$context = Get-MgContext
Write-Host "Connected to tenant $($context.TenantId) as $($context.Account)" -ForegroundColor Green

# ---------------------------------------------------------------- helpers
function Test-EcommMatch {
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

function Expand-ProxyAddress {
    param([string]$Raw)

    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }

    $prefix  = ''
    $address = $Raw
    if ($Raw -match '^(?<p>[^:]+):(?<a>.*)$') {
        $prefix  = $Matches['p']
        $address = $Matches['a']
    }

    # Case is significant: upper-case SMTP marks the primary address.
    $type = if ($prefix -ceq 'SMTP')      { 'Primary SMTP' }
            elseif ($prefix -ceq 'smtp')  { 'Alias SMTP' }
            elseif ($prefix -match '(?i)^x500$') { 'X500' }
            elseif ($prefix -match '(?i)^sip$')  { 'SIP' }
            elseif ($prefix)              { $prefix }
            else                          { 'Unqualified' }

    [pscustomobject]@{ AddressType = $type; Address = $address; Raw = $Raw }
}

$addressRecords = New-Object System.Collections.Generic.List[object]

function Add-AddressRows {
    param($Record, [string]$ObjectKind, [string]$Source = 'Entra')

    $emitted = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)

    $emit = {
        param([string]$Type, [string]$Address)
        if ([string]::IsNullOrWhiteSpace($Address)) { return }
        if (-not $emitted.Add($Address)) { return }
        $addressRecords.Add([pscustomobject]@{
            Source      = $Source
            ObjectKind  = $ObjectKind
            ObjectName  = $Record.DisplayName
            UPNorAlias  = $Record.UserPrincipalName
            AddressType = $Type
            Address     = $Address
            ObjectId    = $Record.Id
            EcommMatch  = $Record.EcommMatch
        })
    }

    foreach ($raw in ($Record.ProxyAddresses -split ';')) {
        $parsed = Expand-ProxyAddress -Raw $raw
        if (-not $parsed) { continue }
        & $emit $parsed.AddressType $parsed.Address
    }

    & $emit 'mail attribute' $Record.PrimaryEmail
}

function Write-Csv {
    param($Data, [string]$FileName)
    $path = Join-Path $OutputPath $FileName
    if ($Data -and @($Data).Count -gt 0) {
        @($Data) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    else {
        Set-Content -Path $path -Value '' -Encoding UTF8
    }
    Write-Host ("  {0,-42} {1,6} rows" -f $FileName, @($Data).Count)
}

# ---------------------------------------------------------------- users
Write-Host 'Querying Entra users...' -ForegroundColor Cyan

$userProps = @(
    'id','displayName','userPrincipalName','mail','proxyAddresses','department',
    'jobTitle','companyName','accountEnabled','userType','onPremisesSyncEnabled',
    'onPremisesSamAccountName','onPremisesDistinguishedName','createdDateTime'
)

$entraUsers = Get-MgUser -All -Property $userProps -ConsistencyLevel eventual

$userRecords = foreach ($u in $entraUsers) {
    [pscustomobject]@{
        ObjectType        = 'User'
        Id                = $u.Id
        DisplayName       = $u.DisplayName
        UserPrincipalName = $u.UserPrincipalName
        PrimaryEmail      = $u.Mail
        ProxyAddresses    = ($u.ProxyAddresses -join ';')
        Department        = $u.Department
        JobTitle          = $u.JobTitle
        Company           = $u.CompanyName
        AccountEnabled    = $u.AccountEnabled
        UserType          = $u.UserType
        SyncedFromAD      = $u.OnPremisesSyncEnabled
        OnPremSam         = $u.OnPremisesSamAccountName
        OnPremDN          = $u.OnPremisesDistinguishedName
        CreatedDateTime   = $u.CreatedDateTime
        EcommMatch        = (Test-EcommMatch -InputObject $u -Pattern $EcommPattern -Fields @(
                                'DisplayName','UserPrincipalName','Mail','ProxyAddresses','Department',
                                'JobTitle','CompanyName','OnPremisesSamAccountName','OnPremisesDistinguishedName'))
    }
}

# ---------------------------------------------------------------- groups
Write-Host 'Querying Entra groups...' -ForegroundColor Cyan

$groupProps = @(
    'id','displayName','description','mail','mailNickname','proxyAddresses',
    'groupTypes','mailEnabled','securityEnabled','visibility','createdDateTime',
    'onPremisesSyncEnabled','onPremisesSamAccountName','membershipRule'
)

$entraGroups = Get-MgGroup -All -Property $groupProps -ConsistencyLevel eventual

function Get-GroupKind {
    param($Group)

    $types = @($Group.GroupTypes)
    $kind =
        if ($types -contains 'Unified')                            { 'Microsoft 365 Group' }
        elseif ($Group.MailEnabled -and $Group.SecurityEnabled)    { 'Mail-Enabled Security Group' }
        elseif ($Group.MailEnabled)                                { 'Distribution Group' }
        elseif ($Group.SecurityEnabled)                            { 'Security Group' }
        else                                                       { 'Other' }

    if ($types -contains 'DynamicMembership') { $kind = "$kind (Dynamic)" }
    return $kind
}

$groupRecords = foreach ($g in $entraGroups) {
    [pscustomobject]@{
        ObjectType      = 'Group'
        GroupType       = (Get-GroupKind -Group $g)
        Id              = $g.Id
        DisplayName     = $g.DisplayName
        PrimaryEmail    = $g.Mail
        MailNickname    = $g.MailNickname
        ProxyAddresses  = ($g.ProxyAddresses -join ';')
        MailEnabled     = $g.MailEnabled
        SecurityEnabled = $g.SecurityEnabled
        GroupTypes      = (@($g.GroupTypes) -join ';')
        Description     = $g.Description
        Visibility      = $g.Visibility
        MembershipRule  = $g.MembershipRule
        SyncedFromAD    = $g.OnPremisesSyncEnabled
        OnPremSam       = $g.OnPremisesSamAccountName
        CreatedDateTime = $g.CreatedDateTime
        EcommMatch      = (Test-EcommMatch -InputObject $g -Pattern $EcommPattern -Fields @(
                              'DisplayName','Mail','MailNickname','ProxyAddresses','Description',
                              'OnPremisesSamAccountName','MembershipRule'))
    }
}

# ---------------------------------------------------------------- ecomm membership
Write-Host 'Expanding membership of ecomm groups...' -ForegroundColor Cyan

$ecommGroups   = @($groupRecords | Where-Object EcommMatch)
$memberRecords = New-Object System.Collections.Generic.List[object]

foreach ($g in $ecommGroups) {
    try {
        $members = Get-MgGroupMember -GroupId $g.Id -All
    }
    catch {
        Write-Warning "Could not expand '$($g.DisplayName)': $($_.Exception.Message.Trim())"
        continue
    }

    foreach ($m in $members) {
        $extra = $m.AdditionalProperties
        $memberRecords.Add([pscustomobject]@{
            GroupName   = $g.DisplayName
            GroupType   = $g.GroupType
            GroupEmail  = $g.PrimaryEmail
            GroupId     = $g.Id
            MemberId    = $m.Id
            MemberName  = $extra['displayName']
            MemberUPN   = $extra['userPrincipalName']
            MemberEmail = $extra['mail']
            MemberType  = ($extra['@odata.type'] -replace '^#microsoft\.graph\.','')
        })
    }
}

# ---------------------------------------------------------------- Exchange Online
$exchangeRecords = @()

if ($IncludeExchangeOnline) {
    Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warning "ExchangeOnlineManagement is not installed - skipping Exchange recipients. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    }
    else {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $eolArgs = @{ ShowBanner = $false }
        if ($context.Account) { $eolArgs['UserPrincipalName'] = $context.Account }
        Connect-ExchangeOnline @eolArgs

        Write-Host 'Querying Exchange recipients...' -ForegroundColor Cyan

        # Get-Recipient covers every mail-enabled object type in one pass.
        $recipients = Get-Recipient -ResultSize Unlimited

        $exchangeRecords = foreach ($r in $recipients) {
            [pscustomobject]@{
                ObjectType        = 'ExchangeRecipient'
                RecipientType     = [string]$r.RecipientType
                RecipientDetails  = [string]$r.RecipientTypeDetails
                DisplayName       = $r.DisplayName
                Alias             = $r.Alias
                PrimaryEmail      = [string]$r.PrimarySmtpAddress
                ProxyAddresses    = ((@($r.EmailAddresses) | ForEach-Object { [string]$_ }) -join ';')
                Department        = $r.Department
                Company           = $r.Company
                HiddenFromGAL     = $r.HiddenFromAddressListsEnabled
                Id                = [string]$r.ExternalDirectoryObjectId
                DistinguishedName = [string]$r.DistinguishedName
                EcommMatch        = (Test-EcommMatch -InputObject $r -Pattern $EcommPattern -Fields @(
                                        'DisplayName','Alias','PrimarySmtpAddress','EmailAddresses',
                                        'Department','Company','Name','DistinguishedName'))
            }
        }

        # Dynamic distribution groups are recipients, but their filter is worth capturing.
        try {
            $dynamic = Get-DynamicDistributionGroup -ResultSize Unlimited
            $dynamicRecords = foreach ($d in $dynamic) {
                [pscustomobject]@{
                    DisplayName    = $d.DisplayName
                    PrimaryEmail   = [string]$d.PrimarySmtpAddress
                    Alias          = $d.Alias
                    RecipientFilter= [string]$d.RecipientFilter
                    IncludedTypes  = ((@($d.IncludedRecipients) | ForEach-Object { [string]$_ }) -join ';')
                    EcommMatch     = (Test-EcommMatch -InputObject $d -Pattern $EcommPattern -Fields @(
                                          'DisplayName','Alias','PrimarySmtpAddress','RecipientFilter','Name'))
                }
            }
            Write-Csv $dynamicRecords              'eol_dynamic_distribution_groups.csv'
            Write-Csv ($dynamicRecords | Where-Object EcommMatch) 'eol_ecomm_dynamic_distribution_groups.csv'
        }
        catch {
            Write-Warning "Dynamic distribution group query failed: $($_.Exception.Message.Trim())"
        }
    }
}

# ---------------------------------------------------------------- flatten addresses
Write-Host 'Flattening address list...' -ForegroundColor Cyan

foreach ($r in $userRecords)  { Add-AddressRows -Record $r -ObjectKind 'User' }
foreach ($r in $groupRecords) { Add-AddressRows -Record $r -ObjectKind $r.GroupType }
foreach ($r in $exchangeRecords) {
    Add-AddressRows -Record $r -ObjectKind $r.RecipientDetails -Source 'ExchangeOnline'
}

# ---------------------------------------------------------------- write output
Write-Host 'Writing CSV files...' -ForegroundColor Cyan

Write-Csv $userRecords                                                             'entra_users_all.csv'
Write-Csv $groupRecords                                                            'entra_groups_all.csv'
Write-Csv ($groupRecords | Where-Object { $_.GroupType -like 'Distribution Group*' })          'entra_groups_distribution.csv'
Write-Csv ($groupRecords | Where-Object { $_.GroupType -like 'Security Group*' })              'entra_groups_security.csv'
Write-Csv ($groupRecords | Where-Object { $_.GroupType -like 'Mail-Enabled Security Group*' }) 'entra_groups_mail_enabled_security.csv'
Write-Csv ($groupRecords | Where-Object { $_.GroupType -like 'Microsoft 365 Group*' })         'entra_groups_m365.csv'
Write-Csv $addressRecords                                                          'entra_addresses_all.csv'

Write-Csv ($userRecords    | Where-Object EcommMatch)                              'entra_ecomm_users.csv'
Write-Csv ($groupRecords   | Where-Object EcommMatch)                              'entra_ecomm_groups.csv'
Write-Csv ($addressRecords | Where-Object EcommMatch)                              'entra_ecomm_addresses.csv'
Write-Csv $memberRecords                                                           'entra_ecomm_group_members.csv'

if ($IncludeExchangeOnline -and @($exchangeRecords).Count -gt 0) {
    Write-Csv $exchangeRecords                                                     'eol_recipients_all.csv'
    Write-Csv ($exchangeRecords | Where-Object EcommMatch)                         'eol_ecomm_recipients.csv'
}

# ---------------------------------------------------------------- summary
Write-Host ''
Write-Host '=============== ENTRA SUMMARY ==============' -ForegroundColor Green
Write-Host ("Users                        : {0}" -f @($userRecords).Count)
Write-Host ("Groups (all)                 : {0}" -f @($groupRecords).Count)
Write-Host ("  Distribution groups        : {0}" -f @($groupRecords | Where-Object { $_.GroupType -like 'Distribution Group*' }).Count)
Write-Host ("  Security groups            : {0}" -f @($groupRecords | Where-Object { $_.GroupType -like 'Security Group*' }).Count)
Write-Host ("  Mail-enabled security      : {0}" -f @($groupRecords | Where-Object { $_.GroupType -like 'Mail-Enabled Security Group*' }).Count)
Write-Host ("  Microsoft 365 groups       : {0}" -f @($groupRecords | Where-Object { $_.GroupType -like 'Microsoft 365 Group*' }).Count)
if ($IncludeExchangeOnline) {
    Write-Host ("Exchange recipients          : {0}" -f @($exchangeRecords).Count)
}
Write-Host ("Distinct address rows        : {0}" -f $addressRecords.Count)
Write-Host '--------------- ECOMM MATCHES --------------' -ForegroundColor Yellow
Write-Host ("Pattern                      : {0}" -f $EcommPattern)
Write-Host ("Ecomm users                  : {0}" -f @($userRecords | Where-Object EcommMatch).Count)
Write-Host ("Ecomm groups                 : {0}" -f $ecommGroups.Count)
Write-Host ("Ecomm address rows           : {0}" -f @($addressRecords | Where-Object EcommMatch).Count)
Write-Host ("Ecomm group member rows      : {0}" -f $memberRecords.Count)
if ($IncludeExchangeOnline) {
    Write-Host ("Ecomm Exchange recipients    : {0}" -f @($exchangeRecords | Where-Object EcommMatch).Count)
}
Write-Host '============================================' -ForegroundColor Green
