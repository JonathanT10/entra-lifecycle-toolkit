# Entra Lifecycle Toolkit

PowerShell scripts for the full employee lifecycle in Microsoft Entra ID — provision on day one, cleanly revoke on the last day, and prove it afterward. Built by an IT manager who runs this process for real, generalized so any Microsoft 365 tenant can use it.

| Script | What it does |
|---|---|
| `scripts/New-EmployeeOnboard.ps1` | Creates the user from a role template: profile, manager, groups, licenses, and a Temporary Access Pass for first sign-in |
| `scripts/Start-EmployeeOffboard.ps1` | The departure sequence in the right order: disable sign-in, revoke sessions, strip groups and app assignments, convert the mailbox to shared, forward mail, remove licenses — with a full audit transcript |
| `scripts/Get-OffboardAudit.ps1` | Read-only sweep that verifies a leaver has no residual access: groups, roles, apps, licenses, devices — PASS/REVIEW per category |

## Why templates?

Onboarding goes wrong when each hire is assembled by hand. A role template pins down what a "sales rep" or "service tech" gets — groups, licenses, department, title — so provisioning is one command and every hire in that role looks the same:

```powershell
.\New-EmployeeOnboard.ps1 -GivenName Jane -Surname Doe -Role sales-rep -Domain contoso.com -ManagerUpn boss@contoso.com
```

Templates live in `templates/role-templates.json`. Copy the sample, rename the roles to yours, and point the group names at real Entra ID groups.

## Setup

1. **Install the Microsoft Graph PowerShell SDK** (PowerShell 7 recommended):

   ```powershell
   Install-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users.Actions, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
   Install-Module ExchangeOnlineManagement -Scope CurrentUser   # for the mailbox steps
   ```

2. **Connect with the right scopes** (the scripts will prompt if you haven't):

   ```powershell
   Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All","AppRoleAssignment.ReadWrite.All","AuditLog.Read.All"
   Connect-ExchangeOnline   # only needed for offboarding mailbox steps
   ```

3. **Dry-run first.** Every mutating script supports `-WhatIf`:

   ```powershell
   .\Start-EmployeeOffboard.ps1 -UserPrincipalName jdoe@contoso.com -WhatIf
   ```

## The offboarding sequence

```powershell
# 1. Day-of-departure: cut access and preserve mail
.\Start-EmployeeOffboard.ps1 -UserPrincipalName jdoe@contoso.com -ForwardTo manager@contoso.com

# 2. After the shared-mailbox conversion has completed: reclaim licenses
.\Start-EmployeeOffboard.ps1 -UserPrincipalName jdoe@contoso.com -RemoveLicenses

# 3. Verify nothing is left
.\Get-OffboardAudit.ps1 -UserPrincipalName jdoe@contoso.com
```

Why two passes? Removing the license of a mailbox that hasn't finished converting to shared can destroy mailbox data after the grace period. The script warns about this; the two-step flow avoids it entirely.

Deliberately skipped and logged, not silently ignored: dynamic groups (membership is rule-based), and distribution/mail-enabled security groups (those are managed in Exchange Online, not Graph).

## Notes and caveats

- **Test in a dev tenant first.** These scripts mutate identity objects. `-WhatIf` shows the plan, but a [Microsoft 365 Developer tenant](https://developer.microsoft.com/microsoft-365/dev-program) is the right place for a first run.
- Temporary Access Pass requires the TAP authentication method policy to be enabled in the tenant; the onboard script falls back to a one-time password (change forced at first sign-in) when it isn't.
- Transcripts of every run land in `logs/` (git-ignored) — attach them to the HR ticket.
- Nothing here stores credentials. Authentication is interactive `Connect-MgGraph` / `Connect-ExchangeOnline`; for unattended use, wire the scripts to a certificate-based app registration instead.

## Roadmap

- Intune device retire/wipe step in the offboard flow
- Teams webhook notifications on completion
- Example HR-trigger wiring (Power Automate → runbook)
- Pester tests against Graph mocks

## License

MIT — see [LICENSE](LICENSE).
