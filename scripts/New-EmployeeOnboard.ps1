<#
.SYNOPSIS
    Provisions a new employee in Microsoft Entra ID from a role template.

.DESCRIPTION
    Creates the Entra ID user, sets core profile attributes, assigns the manager,
    adds group memberships and license SKUs defined in a role template (JSON),
    and issues a Temporary Access Pass (TAP) for first sign-in where the tenant
    allows it (falls back to a generated one-time password otherwise).

    Every action is written to a timestamped transcript so the provisioning run
    is fully auditable.

    Designed for interactive admin use or as the core of an HR-triggered
    automation. Test in a dev tenant before pointing it at production.

.PARAMETER GivenName
    The new employee's first name.

.PARAMETER Surname
    The new employee's last name.

.PARAMETER Role
    Role template name. Must match a key in the role template JSON file
    (see -TemplatePath), e.g. "sales-rep" or "service-tech".

.PARAMETER Domain
    UPN suffix for the new account, e.g. "contoso.com".

.PARAMETER ManagerUpn
    UPN of the new employee's manager. Optional.

.PARAMETER Department
    Department attribute. Optional; falls back to the role template's
    department value when present.

.PARAMETER JobTitle
    Job title attribute. Optional; falls back to the role template's
    jobTitle value when present.

.PARAMETER TemplatePath
    Path to the role template JSON. Defaults to ..\templates\role-templates.json
    relative to this script.

.PARAMETER UsageLocation
    Two-letter ISO country code required for license assignment. Default: US.

.EXAMPLE
    .\New-EmployeeOnboard.ps1 -GivenName Jane -Surname Doe -Role sales-rep -Domain contoso.com -ManagerUpn boss@contoso.com

    Creates jane.doe@contoso.com from the "sales-rep" template, assigns her
    manager, groups, and licenses, and prints a provisioning summary with a TAP.

.EXAMPLE
    .\New-EmployeeOnboard.ps1 -GivenName Jane -Surname Doe -Role sales-rep -Domain contoso.com -WhatIf

    Shows every action the script would take without changing anything.

.NOTES
    Required Graph scopes:
        User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All,
        UserAuthenticationMethod.ReadWrite.All
    Required modules:
        Microsoft.Graph.Users, Microsoft.Graph.Groups,
        Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users.Actions
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$GivenName,
    [Parameter(Mandatory)][string]$Surname,
    [Parameter(Mandatory)][string]$Role,
    [Parameter(Mandatory)][string]$Domain,
    [string]$ManagerUpn,
    [string]$Department,
    [string]$JobTitle,
    [string]$TemplatePath = (Join-Path $PSScriptRoot '..\templates\role-templates.json'),
    [ValidatePattern('^[A-Z]{2}$')][string]$UsageLocation = 'US'
)

$ErrorActionPreference = 'Stop'

#region Setup and validation
$requiredModules = @(
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.SignIns'
)
foreach ($m in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser"
    }
}

if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All','Directory.ReadWrite.All','UserAuthenticationMethod.ReadWrite.All' -NoWelcome
}

if (-not (Test-Path $TemplatePath)) {
    throw "Role template file not found: $TemplatePath"
}
$templates = Get-Content $TemplatePath -Raw | ConvertFrom-Json
$template  = $templates.roles.$Role
if (-not $template) {
    $available = ($templates.roles.PSObject.Properties.Name) -join ', '
    throw "Role '$Role' not found in $TemplatePath. Available roles: $available"
}

$logDir = Join-Path $PSScriptRoot '..\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir ("onboard-{0}{1}-{2}.log" -f $GivenName.ToLower(), $Surname.ToLower(), (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $logFile | Out-Null
#endregion

try {
    #region Build identity
    $mailNickname = ('{0}.{1}' -f $GivenName, $Surname).ToLower() -replace '[^a-z0-9.]',''
    $upn          = '{0}@{1}' -f $mailNickname, $Domain
    $displayName  = '{0} {1}' -f $GivenName, $Surname

    if (Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue) {
        throw "A user with UPN '$upn' already exists. Resolve the collision and re-run."
    }

    # One-time password used only if a TAP cannot be issued.
    $charPool = [char[]]('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%'.ToCharArray())
    $tempPassword = -join (1..20 | ForEach-Object { $charPool | Get-Random })
    #endregion

    #region Create user
    $userParams = @{
        DisplayName       = $displayName
        GivenName         = $GivenName
        Surname           = $Surname
        UserPrincipalName = $upn
        MailNickname      = $mailNickname
        AccountEnabled    = $true
        UsageLocation     = $UsageLocation
        PasswordProfile   = @{
            Password                      = $tempPassword
            ForceChangePasswordNextSignIn = $true
        }
    }
    $resolvedDepartment = if ($Department) { $Department } elseif ($template.department) { $template.department } else { $null }
    $resolvedTitle      = if ($JobTitle)   { $JobTitle }   elseif ($template.jobTitle)   { $template.jobTitle }   else { $null }
    if ($resolvedDepartment) { $userParams.Department = $resolvedDepartment }
    if ($resolvedTitle)      { $userParams.JobTitle   = $resolvedTitle }

    $user = $null
    if ($PSCmdlet.ShouldProcess($upn, 'Create Entra ID user')) {
        $user = New-MgUser @userParams
        Write-Host "[+] Created user $upn (Id: $($user.Id))"
    }
    #endregion

    #region Assign manager
    if ($ManagerUpn -and $user) {
        $manager = Get-MgUser -Filter "userPrincipalName eq '$ManagerUpn'"
        if ($manager) {
            if ($PSCmdlet.ShouldProcess($upn, "Set manager to $ManagerUpn")) {
                Set-MgUserManagerByRef -UserId $user.Id -BodyParameter @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($manager.Id)"
                }
                Write-Host "[+] Manager set: $ManagerUpn"
            }
        }
        else {
            Write-Warning "Manager '$ManagerUpn' not found - skipped."
        }
    }
    #endregion

    #region Group memberships
    $groupResults = @()
    foreach ($groupName in @($template.groups)) {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'"
        if (-not $group) {
            Write-Warning "Group '$groupName' not found - skipped."
            $groupResults += [pscustomobject]@{ Group = $groupName; Status = 'NOT FOUND' }
            continue
        }
        if ($group.Count -gt 1) {
            Write-Warning "Group name '$groupName' is ambiguous ($($group.Count) matches) - skipped. Use a unique name."
            $groupResults += [pscustomobject]@{ Group = $groupName; Status = 'AMBIGUOUS' }
            continue
        }
        if ($group.GroupTypes -contains 'DynamicMembership') {
            Write-Host "[i] '$groupName' is dynamic - membership will be evaluated by its rule."
            $groupResults += [pscustomobject]@{ Group = $groupName; Status = 'DYNAMIC (rule-based)' }
            continue
        }
        if ($user -and $PSCmdlet.ShouldProcess($upn, "Add to group '$groupName'")) {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id
            Write-Host "[+] Added to group: $groupName"
            $groupResults += [pscustomobject]@{ Group = $groupName; Status = 'ADDED' }
        }
    }
    #endregion

    #region License assignment
    $licenseResults = @()
    if (@($template.licenses).Count -gt 0 -and $user) {
        $tenantSkus = Get-MgSubscribedSku
        $addLicenses = @()
        foreach ($skuPart in @($template.licenses)) {
            $sku = $tenantSkus | Where-Object SkuPartNumber -eq $skuPart
            if (-not $sku) {
                Write-Warning "License SKU '$skuPart' not found in tenant - skipped."
                $licenseResults += [pscustomobject]@{ Sku = $skuPart; Status = 'NOT FOUND' }
                continue
            }
            $freeSeats = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
            if ($freeSeats -lt 1) {
                Write-Warning "License SKU '$skuPart' has no available seats ($($sku.ConsumedUnits)/$($sku.PrepaidUnits.Enabled) used) - skipped."
                $licenseResults += [pscustomobject]@{ Sku = $skuPart; Status = 'NO SEATS' }
                continue
            }
            $addLicenses += @{ SkuId = $sku.SkuId }
            $licenseResults += [pscustomobject]@{ Sku = $skuPart; Status = 'ASSIGNED' }
        }
        if ($addLicenses.Count -gt 0 -and $PSCmdlet.ShouldProcess($upn, "Assign licenses: $(@($template.licenses) -join ', ')")) {
            Set-MgUserLicense -UserId $user.Id -AddLicenses $addLicenses -RemoveLicenses @() | Out-Null
            Write-Host "[+] Licenses assigned."
        }
    }
    #endregion

    #region First sign-in credential (TAP with password fallback)
    $firstSignIn = $null
    if ($user -and $PSCmdlet.ShouldProcess($upn, 'Issue Temporary Access Pass')) {
        try {
            $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -BodyParameter @{
                isUsableOnce      = $false
                lifetimeInMinutes = 480
            }
            $firstSignIn = "Temporary Access Pass (8h): $($tap.TemporaryAccessPass)"
            Write-Host '[+] Temporary Access Pass issued (valid 8 hours).'
        }
        catch {
            $firstSignIn = "One-time password: $tempPassword (change forced at first sign-in)"
            Write-Warning "TAP could not be issued (policy may be disabled): $($_.Exception.Message)"
        }
    }
    #endregion

    #region Summary
    if ($user) {
        Write-Host ''
        Write-Host '================ PROVISIONING SUMMARY ================'
        Write-Host "  User:        $displayName <$upn>"
        Write-Host "  Object Id:   $($user.Id)"
        Write-Host "  Role:        $Role"
        if ($resolvedDepartment) { Write-Host "  Department:  $resolvedDepartment" }
        if ($resolvedTitle)      { Write-Host "  Title:       $resolvedTitle" }
        if ($ManagerUpn)         { Write-Host "  Manager:     $ManagerUpn" }
        Write-Host '  Groups:'
        $groupResults   | ForEach-Object { Write-Host ("    - {0}: {1}" -f $_.Group, $_.Status) }
        Write-Host '  Licenses:'
        $licenseResults | ForEach-Object { Write-Host ("    - {0}: {1}" -f $_.Sku, $_.Status) }
        if ($firstSignIn) { Write-Host "  First sign-in: $firstSignIn" }
        Write-Host "  Log:         $logFile"
        Write-Host '======================================================'
    }
    #endregion
}
finally {
    Stop-Transcript | Out-Null
}
