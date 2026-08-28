<#
.SYNOPSIS
    Audits a departed user for residual access after offboarding.

.DESCRIPTION
    Read-only sweep of everything an offboarded account can still touch:

      - Account state (enabled/disabled) and last sign-in activity
      - Remaining group memberships (flagging assigned vs. dynamic)
      - Remaining directly-assigned licenses
      - Direct enterprise-app role assignments
      - Registered and owned devices
      - Directory roles still held (should always be none for a leaver)

    Emits a structured report object (pipe it to ConvertTo-Json, Export-Csv, or
    Format-List) and prints a PASS/REVIEW verdict per category. Makes no changes.

.PARAMETER UserPrincipalName
    UPN of the offboarded user to audit.

.PARAMETER AsJson
    Emit the report as JSON instead of a PowerShell object.

.EXAMPLE
    .\Get-OffboardAudit.ps1 -UserPrincipalName jdoe@contoso.com

    Prints the audit verdicts and returns the report object.

.EXAMPLE
    .\Get-OffboardAudit.ps1 -UserPrincipalName jdoe@contoso.com -AsJson > jdoe-audit.json

    Saves the full audit as JSON for the offboarding ticket.

.NOTES
    Required Graph scopes (read-only):
        User.Read.All, Group.Read.All, Directory.Read.All, AuditLog.Read.All
    Required modules:
        Microsoft.Graph.Users, Microsoft.Graph.Groups,
        Microsoft.Graph.Identity.DirectoryManagement
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes 'User.Read.All','Group.Read.All','Directory.Read.All','AuditLog.Read.All' -NoWelcome
}

$user = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses,SignInActivity
if (-not $user) { throw "User '$UserPrincipalName' not found." }

#region Collect
$memberships = Get-MgUserMemberOf -UserId $user.Id -All
$groups = $memberships |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } |
    ForEach-Object {
        [pscustomobject]@{
            Name    = $_.AdditionalProperties.displayName
            Type    = if (@($_.AdditionalProperties.groupTypes) -contains 'DynamicMembership') { 'Dynamic' } else { 'Assigned' }
        }
    }
$directoryRoles = $memberships |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' } |
    ForEach-Object { $_.AdditionalProperties.displayName }

$appAssignments = Get-MgUserAppRoleAssignment -UserId $user.Id -All |
    ForEach-Object { $_.ResourceDisplayName } | Sort-Object -Unique

$licenses = @()
if (@($user.AssignedLicenses).Count -gt 0) {
    $tenantSkus = Get-MgSubscribedSku
    $licenses = @($user.AssignedLicenses) | ForEach-Object {
        $skuId = $_.SkuId
        ($tenantSkus | Where-Object SkuId -eq $skuId).SkuPartNumber
    }
}

$registeredDevices = Get-MgUserRegisteredDevice -UserId $user.Id -All |
    ForEach-Object { $_.AdditionalProperties.displayName }
$ownedDevices = Get-MgUserOwnedDevice -UserId $user.Id -All |
    ForEach-Object { $_.AdditionalProperties.displayName }

$lastSignIn = $user.SignInActivity.LastSignInDateTime
#endregion

#region Verdicts
function Get-Verdict {
    param([bool]$Pass, [string]$Category, [string]$Detail)
    $label = if ($Pass) { 'PASS  ' } else { 'REVIEW' }
    Write-Host ("  [{0}] {1}{2}" -f $label, $Category, $(if ($Detail) { " - $Detail" } else { '' }))
    return (-not $Pass)
}

Write-Host ''
Write-Host "Offboard audit: $($user.DisplayName) <$UserPrincipalName>"
Write-Host '--------------------------------------------------------'

$flags = 0
$assignedGroups = @($groups | Where-Object Type -eq 'Assigned')
$flags += Get-Verdict (-not $user.AccountEnabled) 'Account disabled' $(if ($user.AccountEnabled) { 'account is still ENABLED' })
$flags += Get-Verdict ($assignedGroups.Count -eq 0) 'Assigned group memberships' "$($assignedGroups.Count) remaining"
$flags += Get-Verdict (@($directoryRoles).Count -eq 0) 'Directory roles' $(if ($directoryRoles) { ($directoryRoles -join ', ') })
$flags += Get-Verdict (@($appAssignments).Count -eq 0) 'App role assignments' "$(@($appAssignments).Count) remaining"
$flags += Get-Verdict (@($licenses).Count -eq 0) 'Licenses' "$(@($licenses).Count) remaining"
$flags += Get-Verdict (@($registeredDevices).Count -eq 0) 'Registered devices' "$(@($registeredDevices).Count) remaining"

Write-Host '--------------------------------------------------------'
if ($flags -eq 0) {
    Write-Host 'RESULT: CLEAN - no residual access detected.'
}
else {
    Write-Host "RESULT: $flags categor$(if ($flags -eq 1) {'y needs'} else {'ies need'}) review (see above)."
}
Write-Host ''
#endregion

#region Report object
$report = [pscustomobject]@{
    UserPrincipalName  = $user.UserPrincipalName
    DisplayName        = $user.DisplayName
    AuditTimestampUtc  = (Get-Date).ToUniversalTime().ToString('o')
    AccountEnabled     = $user.AccountEnabled
    LastSignIn         = $lastSignIn
    AssignedGroups     = $assignedGroups.Name
    DynamicGroups      = @($groups | Where-Object Type -eq 'Dynamic').Name
    DirectoryRoles     = $directoryRoles
    AppRoleAssignments = $appAssignments
    Licenses           = $licenses
    RegisteredDevices  = $registeredDevices
    OwnedDevices       = $ownedDevices
    CategoriesToReview = $flags
}

if ($AsJson) { $report | ConvertTo-Json -Depth 4 } else { $report }
#endregion
