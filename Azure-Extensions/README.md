# Manage-ArcExtensions
This script will iterate through all Azure Arc systems in a given Resource Group, and either report-on or upgrade any installed extensions where an update is available.  This works whether or not the extension supports auto-upgrade.

Running the script without parameters is the same as running report mode - you'll receive a per-machine list of all extensions where an upgrade is available.  Running it with the -Upgrade parameter will initiate PowerShell jobs to update each extension.

# Pre-Requisites:
The script needs the Az command-line-interface installed, as well as the Az.ConnectedMachine module.
1) Install-Module Az.ConnectedMachine
2) Install the Az cli package.  This can be downloaded from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli or it can be installed via WinGet: winget install -e --id Microsoft.AzureCLI

# Usage
You can set the -ResourceGroup parameter to the name of the Resource Group containing the systems you'd like to assess.
Otherwise a default of 'ArcRG' is assumed
Use the -Update parameter to permit updates otherwise the script will run in report mode only

The script assumes you're already logged in to Azure (Connect-AzAccount) and have set the target subscription to be managed when you logged in.
