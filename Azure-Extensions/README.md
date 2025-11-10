# Manage-ArcExtensions

## Disclaimer

This code is provided for demonstration purposes only.
It is intended to illustrate concepts and should not be used in production environments without proper review, testing, and validation.
The authors and distributors of this code make no warranties regarding its functionality, security, or suitability for any specific use.
Use at your own risk.

## Synopsis

This script will iterate through all Azure Arc systems in a given Resource Group, and either report-on or upgrade any installed extensions where an update is available.  This works whether or not the extension supports auto-upgrade.

Running the script without parameters is the same as running report mode - you'll receive a per-machine list of all extensions where an upgrade is available.  Running it with the -Upgrade parameter will initiate PowerShell jobs to update each extension.

Running the script without parameters is the same as running with the -CheckOnly option - you'll receive a per-machine list of all extensions where an upgrade is available.  Running it with the -Upgrade parameter will initiate PowerShell jobs to update each extension.

Pre-Requisites:

## Pre-Requisites

The script needs the Az command-line-interface installed, as well as the Az.ConnectedMachine module.

1) Install-Module Az.ConnectedMachine

2) Install the Az cli package.  This can be downloaded from [https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli] or it can be installed via WinGet: winget install -e --id Microsoft.AzureCLI

## Usage

You can set the -ResourceGroup parameter to the name of the Resource Group containing the systems you'd like to assess.
Otherwise a default of 'ArcRG' is assumed
Use the -Update parameter to permit updates otherwise the script will run in report mode only

The script assumes you're already logged in to Azure (Connect-AzAccount) and have set the target subscription to be managed when you logged in.
2) Install the Az cli package.  This can be downloaded from  [https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli]  or it can be installed via WinGet: winget install -e --id Microsoft.AzureCLI
3) Update the $resourceGroup variable to the name of the Resource Group containing the systems you'd like to assess.  The script assumes you're already logged in to Azure and have set the subscription to be managed when you logged in.

## Contributing

Guidelines for contributing to your project.

1. Fork the repository
2. Create a new branch (git checkout -b feature-branch)
3. Make your changes
4. Commit your changes (git commit -m 'Add some feature')
5. Push to the branch (git push origin feature-branch)
6. Open a pull request

## License

MIT license.

## Contact

How to reach you for questions or feedback.

Email: <GitHub@ffournier.ca>
GitHub: Frafou
