<#
.SYNOPSIS
    Standardized, audited offboarding of a departed employee in Microsoft Entra ID
    and Exchange Online.

.DESCRIPTION
    Runs the offboarding sequence most orgs assemble by hand, in the right order,
    and writes an audit transcript of every step:

      1. Disable sign-in (accountEnabled = false)
      2. Revoke all refresh tokens / active sessions
      3. Remove assigned (non-dynamic) group memberships
      4. Remove app role assignments (optional, -RemoveAppAssignments)
      5. Convert the mailbox to a shared mailbox and hide it from the GAL
      6. Set mail forwarding to a delegate (optional, -ForwardTo)
      7. Remove license SKUs (optional, -RemoveLicenses; run AFTER the shared-mailbox
         conversion has completed, or mailbox data can be lost)

    Steps that need Exchange Online are skipped with a warning when the
    ExchangeOnlineManagement module isn't connected.

    Everything supports -WhatIf. Test in a dev tenant before production use.

.PARAMETER UserPrincipalName
    UPN of the employee being offboarded.

.PARAMETER ForwardTo
    UPN or SMTP address that should receive the departed user's mail.
    Sets ForwardingSmtpAddress with DeliverToMailboxAndForward disabled.

.PARAMETER RemoveLicenses
    Also strip all directly-assigned license SKUs. Leave this OFF on the first
    pass if you convert to a shared mailbox in the same run - confirm the
    conversion finished first, then re-run with this switch.

.PARAMETER RemoveAppAssignments
    Also remove the user's direct enterprise-app role assignments.

.PARAMETER SkipMailbox
    Skip all Exchange Online steps (no shared-mailbox conversion, no forwarding,
    no GAL hiding).

.EXAMPLE
    .\Start-EmployeeOffboard.ps1 -UserPrincipalName jdoe@contoso.com -WhatIf

    Dry run - prints every action that would be taken.

.EXAMPLE
    .\Start-EmployeeOffboard.ps1 -UserPrincipalName jdoe@contoso.com -ForwardTo manager@contoso.com

    Disables the account, revokes sessions, strips groups, converts the mailbox
    to shared, hides it from the GAL, and forwards mail to the manager.

.NOTES
    Required Graph scopes:
        User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All,
        AppRoleAssignment.ReadWrite.All
    Exchange steps additionally require Connect-ExchangeOnline with an
    Exchange administrator role.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$ForwardTo,
    [switch]$RemoveLicenses,
    [switch]$RemoveAppAssignments,
    [switch]$SkipMailbox
)

$ErrorActionPreference = 'Stop'

#region Setup
$requiredModules = @('Microsoft.Graph.Users','Microsoft.Graph.Groups','Microsoft.Graph.Users.Actions')
foreach ($m in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser"
    }
}
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All','Directory.ReadWrite.All','AppRoleAssignment.ReadWrite.All' -NoWelcome
}

$exoAvailable = $false
if (-not $SkipMailbox) {
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
        $exoAvailable = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue)
        if (-not $exoAvailable) {
            Write-Warning 'ExchangeOnlineManagement is installed but not connected (Connect-ExchangeOnline). Mailbox steps will be SKIPPED.'
        }
    }
    else {
        Write-Warning 'ExchangeOnlineManagement module not installed. Mailbox steps will be SKIPPED.'
    }
}

$user = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses
if (-not $user) { throw "User '$UserPrincipalName' not found." }

$logDir = Join-Path $PSScriptRoot '..\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir ("offboard-{0}-{1}.log" -f ($UserPrincipalName -replace '[@.]','-'), (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $logFile | Out-Null

$actions = @()
function Add-Action { param($Step,$Status,$Detail) $script:actions += [pscustomobject]@{ Step = $Step; Status = $Status; Detail = $Detail } }
#endregion

try {
    Write-Host "Offboarding $($user.DisplayName) <$UserPrincipalName>"
    Write-Host ''

    #region 1. Disable sign-in
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Disable sign-in')) {
        Update-MgUser -UserId $user.Id -AccountEnabled:$false
        Write-Host '[+] Sign-in disabled.'
        Add-Action 'Disable sign-in' 'DONE' $null
    } else { Add-Action 'Disable sign-in' 'SKIPPED (WhatIf/declined)' $null }
    #endregion

    #region 2. Revoke sessions
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Revoke all sessions and refresh tokens')) {
        Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
        Write-Host '[+] All sessions and refresh tokens revoked.'
        Add-Action 'Revoke sessions' 'DONE' $null
    } else { Add-Action 'Revoke sessions' 'SKIPPED (WhatIf/declined)' $null }
    #endregion

    #region 3. Remove group memberships
    $memberships = Get-MgUserMemberOf -UserId $user.Id -All
    $groups = $memberships | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
    foreach ($g in $groups) {
        $gName    = $g.AdditionalProperties.displayName
        $gTypes   = @($g.AdditionalProperties.groupTypes)
        $mailEnabled = $g.AdditionalProperties.mailEnabled
        $secEnabled  = $g.AdditionalProperties.securityEnabled
        if ($gTypes -contains 'DynamicMembership') {
            Write-Host "[i] Skipping dynamic group: $gName (membership is rule-based)"
            Add-Action "Group: $gName" 'SKIPPED' 'Dynamic membership'
            continue
        }
        if ($mailEnabled -and -not ($gTypes -contains 'Unified')) {
            Write-Warning "Skipping '$gName': distribution/mail-enabled security groups must be managed in Exchange Online."
            Add-Action "Group: $gName" 'SKIPPED' 'Manage via Exchange Online'
            continue
        }
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove from group '$gName'")) {
            try {
                Remove-MgGroupMemberByRef -GroupId $g.Id -DirectoryObjectId $user.Id
                Write-Host "[+] Removed from group: $gName"
                Add-Action "Group: $gName" 'REMOVED' $null
            }
            catch {
                Write-Warning "Could not remove from '$gName': $($_.Exception.Message)"
                Add-Action "Group: $gName" 'FAILED' $_.Exception.Message
            }
        }
    }
    if (-not $groups) { Write-Host '[i] No group memberships found.' }
    #endregion

    #region 4. App role assignments (optional)
    if ($RemoveAppAssignments) {
        $appAssignments = Get-MgUserAppRoleAssignment -UserId $user.Id -All
        foreach ($a in $appAssignments) {
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove app assignment '$($a.ResourceDisplayName)'")) {
                try {
                    Remove-MgUserAppRoleAssignment -UserId $user.Id -AppRoleAssignmentId $a.Id
                    Write-Host "[+] Removed app assignment: $($a.ResourceDisplayName)"
                    Add-Action "App: $($a.ResourceDisplayName)" 'REMOVED' $null
                }
                catch {
                    Write-Warning "Could not remove app assignment '$($a.ResourceDisplayName)': $($_.Exception.Message)"
                    Add-Action "App: $($a.ResourceDisplayName)" 'FAILED' $_.Exception.Message
                }
            }
        }
        if (-not $appAssignments) { Write-Host '[i] No direct app role assignments found.' }
    }
    #endregion

    #region 5-6. Mailbox conversion, GAL hiding, forwarding
    if ($exoAvailable) {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Convert mailbox to shared and hide from GAL')) {
            Set-Mailbox -Identity $UserPrincipalName -Type Shared
            Set-Mailbox -Identity $UserPrincipalName -HiddenFromAddressListsEnabled $true
            Write-Host '[+] Mailbox converted to shared and hidden from the GAL.'
            Add-Action 'Mailbox to shared + hide from GAL' 'DONE' $null
        }
        if ($ForwardTo) {
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Forward mail to $ForwardTo")) {
                Set-Mailbox -Identity $UserPrincipalName -ForwardingSmtpAddress $ForwardTo -DeliverToMailboxAndForward $false
                Write-Host "[+] Mail forwarding set to $ForwardTo."
                Add-Action "Forwarding to $ForwardTo" 'DONE' $null
            }
        }
    }
    elseif (-not $SkipMailbox) {
        Add-Action 'Mailbox steps' 'SKIPPED' 'Exchange Online not connected'
    }
    #endregion

    #region 7. License removal (optional)
    if ($RemoveLicenses) {
        $assigned = @($user.AssignedLicenses)
        if ($assigned.Count -gt 0) {
            Write-Warning 'Removing licenses. If the shared-mailbox conversion just ran, confirm it completed first - removing the license of a still-user mailbox deletes its data after the grace period.'
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove $($assigned.Count) license(s)")) {
                Set-MgUserLicense -UserId $user.Id -AddLicenses @() -RemoveLicenses ($assigned.SkuId) | Out-Null
                Write-Host "[+] Removed $($assigned.Count) license(s)."
                Add-Action 'Remove licenses' 'DONE' "$($assigned.Count) SKU(s)"
            }
        }
        else {
            Write-Host '[i] No directly-assigned licenses to remove.'
            Add-Action 'Remove licenses' 'NONE FOUND' $null
        }
    }
    else {
        Add-Action 'Remove licenses' 'NOT REQUESTED' 'Re-run with -RemoveLicenses after mailbox conversion completes'
    }
    #endregion

    #region Summary
    Write-Host ''
    Write-Host '================= OFFBOARDING SUMMARY ================='
    Write-Host "  User: $($user.DisplayName) <$UserPrincipalName>"
    $actions | ForEach-Object { Write-Host ("  - {0}: {1}{2}" -f $_.Step, $_.Status, $(if ($_.Detail) { " ($($_.Detail))" } else { '' })) }
    Write-Host "  Log:  $logFile"
    Write-Host '  Next: run Get-OffboardAudit.ps1 to verify no residual access remains.'
    Write-Host '======================================================='
    #endregion
}
finally {
    Stop-Transcript | Out-Null
}
