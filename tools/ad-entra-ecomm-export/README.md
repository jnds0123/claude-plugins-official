# AD + Entra ecomm address export

Read-only PowerShell tooling that pulls **every email address, distribution group,
security group and mail-enabled object** out of on-premises Active Directory and
Entra ID / Exchange Online, then flags everything referencing **ecomm**.

Nothing here writes to a directory or a tenant. Every cmdlet used is a `Get-*`.

## Why two scripts

The two directories hold different things, and neither is a superset of the other:

| Object | On-prem AD | Entra ID | Exchange Online |
|---|---|---|---|
| Users and their proxy addresses | yes | yes | yes |
| Distribution groups | yes | yes | yes |
| Security groups | yes | yes | no |
| Mail-enabled security groups | yes | yes | yes |
| Microsoft 365 groups | no | yes | yes |
| Dynamic distribution lists | no | no | yes |
| Shared mailboxes, mail contacts, mail users | partly | no | yes |
| Cloud-only objects | no | yes | yes |
| Unsynced / orphaned on-prem objects | yes | no | no |

Run both, then merge, so cloud-only and on-prem-only objects both surface.

## Prerequisites

**On-prem AD** — RSAT ActiveDirectory module, run as any account that can read the
directory (a standard domain user is normally enough):

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

**Entra ID** — Microsoft Graph SDK, with the `User.Read.All`, `Group.Read.All`,
`GroupMember.Read.All` and `Directory.Read.All` scopes. **Global Reader** covers all
of them:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser   # for -IncludeExchangeOnline
```

Exchange Online additionally needs the **View-Only Recipients** role, which Global
Reader also grants.

## Running it

```powershell
# 1. on-premises Active Directory
.\Export-ADEcomm.ps1 -OutputPath .\ecomm-export-ad

# 2. Entra ID, plus Exchange recipients that exist nowhere else
.\Export-EntraEcomm.ps1 -IncludeExchangeOnline -OutputPath .\ecomm-export-entra

# 3. merge into one deduplicated view
.\Merge-EcommReport.ps1 -ExportPath .\ecomm-export-ad,.\ecomm-export-entra -OutputPath .\ecomm-merged
```

Useful switches:

```powershell
.\Export-ADEcomm.ps1 -Server dc01.contoso.com -SearchBase "OU=Corp,DC=contoso,DC=com"
.\Export-EntraEcomm.ps1 -TenantId contoso.onmicrosoft.com
.\Export-ADEcomm.ps1 -EcommPattern '(?i)(ecomm|webstore|retail-online)'   # widen the net
```

## Output

Each export script writes a full inventory plus an ecomm-filtered subset.

**`Export-ADEcomm.ps1`**

| File | Contents |
|---|---|
| `ad_users_all.csv` | every user, with mail, proxy addresses, department, OU |
| `ad_groups_all.csv` | every group, classified by type |
| `ad_groups_distribution.csv` | distribution groups only |
| `ad_groups_security.csv` | security groups only |
| `ad_groups_mail_enabled_security.csv` | security groups that also carry addresses |
| `ad_contacts_all.csv` | mail contacts |
| `ad_addresses_all.csv` | one row per address, typed primary / alias / X500 / SIP |
| `ad_ecomm_*.csv` | the ecomm subset of each of the above |
| `ad_ecomm_group_members.csv` | recursive membership of every ecomm group |

**`Export-EntraEcomm.ps1`** writes the same shape with an `entra_` prefix, plus
`entra_groups_m365.csv`, and with `-IncludeExchangeOnline` also
`eol_recipients_all.csv`, `eol_ecomm_recipients.csv` and
`eol_dynamic_distribution_groups.csv`.

**`Merge-EcommReport.ps1`**

| File | Contents |
|---|---|
| `all_addresses_merged.csv` | every address row from every source |
| `all_addresses_unique.csv` | one row per address, listing which sources hold it |
| `ecomm_master.csv` | the ecomm subset — **the deliverable** |
| `ecomm_orphans.csv` | addresses in only one directory, i.e. sync gaps worth reviewing |

Matching is case-insensitive on address, so `JSmith@` and `jsmith@` collapse to one
row with `InAD` and `InCloud` showing where each lives.

## The ecomm pattern

The default `-EcommPattern` is deliberately narrower than a naive `*ecomm*` search:

```
(?-i)(?:(?<![A-Za-z])[Ee]|(?<=[a-z])E)[\s_-]?(?i:comm?(?:erce)?s?)(?=[^a-z]|$)
```

It **matches** `ecomm`, `e-comm`, `e_comm`, `E Commerce`, `ecom`, `ecomms`,
`ecommerce`, and embedded forms like `GRP_Ecomm_Team`, `DL-Ecomm-Orders`,
`OU=Ecomm,DC=...` and camel-case `MyEcommTeam`.

It **does not match** `Telecom`, `Telecommunications`, `Intercom`, `datacom`,
`Welcome Committee`, or addresses at domains that merely end in `e.com`
(`jdoe@adobe.com`, `user@apple.com`, `user@nike.com`) — all of which a simple
substring or `e.*com` search returns as false positives.

Override with `-EcommPattern` if your naming convention differs. Any .NET regex works.

## Review before acting

`EcommMatch` is a heuristic on names, addresses, descriptions, departments and OU
paths. Before using the output to change anything, spot-check `ecomm_master.csv`
against the department roster — a group can belong to ecommerce without ever saying
so in its name, and those will not be flagged.
