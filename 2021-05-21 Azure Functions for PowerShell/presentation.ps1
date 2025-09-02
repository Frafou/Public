# Failsafe
return

<#
Questions?
- Raise Hand
- Unmute and Ask
- Write in Chat
#>

<#
Links:
Recordings: aka.ms/pssession
Materials: aka.ms/pssession-docs
Chat: aka.ms/mspowershell
#>

# Why Azure Functions (And why PowerShell)
<#
- Task Scheduler on Azure
- Secure Delegation
- Integration Automation Workflows

- Already know it
#>

# Setting up a Function App


# Granting Permissions on Resources


# Basic Layout
Set-Location 'C:\Session\PowerShell Azure Functions\DemoFunction'
# PSModuleDevelopment
# Install-Module PSModuleDevelopment
Invoke-PSMDTemplate AzureFunction -Name DemoFunction -Path . -NoFolder
Invoke-PSMDTemplate AzureFunctionRest -Name GetVM

<#
- Get/List VM
- Start VMs
- Stop VMs
#>

# The Pipeline
# Modules