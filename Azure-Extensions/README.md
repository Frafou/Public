# Azure Arc Extensions Management

A PowerShell solution for automated management and updating of Azure Arc server extensions across Resource Groups, providing both reporting and upgrade capabilities for hybrid cloud infrastructure.

## ?? Script Overview

### Manage-AzureArcExtensions.ps1

**Purpose**: Comprehensive Azure Arc server extension lifecycle management

**Key Features**:

- **Automated Discovery**: Scans all Azure Arc systems within specified Resource Groups
- **Extension Inventory**: Reports on all installed extensions and their current versions
- **Update Detection**: Identifies extensions with available updates (auto-upgrade enabled or disabled)
- **Bulk Operations**: Parallel PowerShell jobs for efficient multi-server management
- **Flexible Modes**: Report-only mode for assessment, upgrade mode for automated updates
- **Enterprise Integration**: Compatible with Azure Resource Manager and PowerShell workflows

**Supported Operations**:

- Extension status reporting and inventory management
- Version comparison and update availability detection
- Automated extension updates with progress tracking
- Resource Group-based bulk operations
- Azure Arc server health and connectivity validation

## ?? Quick Start

### Prerequisites

- **Azure PowerShell**: Az.ConnectedMachine module installed
- **Azure CLI**: Latest version for enhanced Azure Arc operations
- **Authentication**: Active Azure session with appropriate permissions
- **Permissions**: Contributor or Azure Arc Administrator role
- **Connectivity**: Network access to Azure Arc servers and Azure APIs
- **PowerShell**: Version 5.1 minimum (PowerShell 7+ recommended)

### Installation

```powershell
# Install required Azure PowerShell modules
Install-Module Az.ConnectedMachine -Force
Install-Module Az.Accounts -Force
Install-Module Az.Resources -Force

# Install Azure CLI (choose one method)
# Method 1: WinGet
winget install -e --id Microsoft.AzureCLI

# Method 2: Direct download
# Download from: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows

# Verify installation
Get-Module Az.ConnectedMachine -ListAvailable
az --version
```

### Authentication Setup

```powershell
# Connect to Azure with PowerShell
Connect-AzAccount

# Set target subscription
Set-AzContext -SubscriptionId "your-subscription-id"

# Verify Azure CLI authentication
az login
az account set --subscription "your-subscription-id"

# Confirm access to Arc resources
Get-AzConnectedMachine -ResourceGroupName "your-rg-name"
```

### Basic Usage

```powershell
# Report mode - assess extensions without making changes
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "ArcRG"

# Report mode with explicit check-only parameter
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "ArcRG" -CheckOnly

# Upgrade mode - automatically update available extensions
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "ArcRG" -Upgrade

# Use default Resource Group (ArcRG)
.\Manage-AzureArcExtensions.ps1

# Verbose output for troubleshooting
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "ArcRG" -Verbose
```

## ?? Use Cases

### 1. Hybrid Infrastructure Management

- Regular assessment of Azure Arc extension health across environments
- Compliance reporting for hybrid cloud governance requirements
- Infrastructure drift detection and remediation planning

### 2. Extension Lifecycle Management

- Automated identification of outdated extensions requiring updates
- Bulk extension updates across multiple Azure Arc servers
- Version consistency enforcement across server fleets

### 3. Security and Compliance

- Extension vulnerability management through timely updates
- Security patch deployment for Azure Arc components
- Audit trail generation for extension management activities

### 4. Operational Efficiency

- Reduced manual effort for multi-server extension management
- Automated extension update workflows integration
- Centralized reporting for Azure Arc extension inventory

## ?? Features

### Automated Discovery

- Resource Group-based Azure Arc server enumeration
- Extension inventory collection with version details
- Connectivity status validation and health checks
- Multi-threaded operations for improved performance

### Intelligent Update Management

- Update availability detection regardless of auto-upgrade settings
- Support for both auto-upgrade enabled and disabled extensions
- Parallel job execution for bulk update operations
- Progress tracking and detailed logging capabilities

### Enterprise Integration

- Azure Resource Manager API compatibility
- PowerShell workflow integration support
- Azure CLI hybrid operations support
- Role-based access control (RBAC) compliance

### Flexible Operation Modes

- **Report Mode**: Non-invasive assessment and inventory generation
- **Upgrade Mode**: Automated extension updates with safety checks
- **Verbose Mode**: Detailed logging for troubleshooting and auditing
- **Resource Group Targeting**: Granular control over scope of operations

## ?? Requirements

### Azure Requirements

- **Azure Subscription**: Active subscription with Arc-enabled servers
- **Resource Groups**: Organized Azure Arc servers in logical groups
- **Azure Arc Agent**: Version 1.0 or higher on target servers
- **Network Connectivity**: HTTPS access to Azure Arc endpoints

### Permissions Required

- **Azure Arc Administrator** (recommended for full functionality)
- **Contributor** role on target Resource Groups
- **Reader** access for report-only operations
- **Connected Machine Resource Administrator** for extension management

### System Requirements

- **Operating System**: Windows 10/11, Windows Server 2016+, Linux distributions
- **PowerShell**: 5.1 minimum, PowerShell 7+ recommended for optimal performance
- **Memory**: 4GB RAM minimum for bulk operations
- **Network**: Stable internet connection for Azure API communication

### Module Dependencies

```powershell
# Required PowerShell modules with minimum versions
Az.Accounts >= 2.0.0
Az.ConnectedMachine >= 0.5.0
Az.Resources >= 4.0.0

# Optional but recommended
Az.Profile >= 1.0.0
ThreadJob >= 2.0.0 (for improved parallel operations)
```

## ?? Advanced Configuration

### Parameter Reference

```powershell
# ResourceGroup parameter
-ResourceGroup "MyArcServers"  # Target specific Resource Group
# Default: "ArcRG" if not specified

# Operation mode parameters
-CheckOnly                     # Explicit report-only mode
-Upgrade                       # Enable extension updates

# Verbose output
-Verbose                       # Detailed logging and progress information
```

### Custom Resource Group Management

```powershell
# Multiple Resource Group operations
$resourceGroups = @("ArcRG-Prod", "ArcRG-Dev", "ArcRG-Test")
foreach ($rg in $resourceGroups) {
    .\Manage-AzureArcExtensions.ps1 -ResourceGroup $rg -CheckOnly
}
```

### Automated Scheduling

```powershell
# Create scheduled task for weekly extension assessment
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Manage-AzureArcExtensions.ps1 -ResourceGroup 'ArcRG' -CheckOnly"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00AM
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "Arc Extension Assessment" `
    -Action $Action -Trigger $Trigger -Settings $Settings
```

## ?? Troubleshooting

### Common Issues

**Issue**: "Module Az.ConnectedMachine not found"
**Solution**: Install required modules using `Install-Module Az.ConnectedMachine -Force`

**Issue**: "Access denied" or "Insufficient permissions"
**Solution**: Verify Azure Arc Administrator or Contributor role assignment

**Issue**: "No Arc servers found in Resource Group"
**Solution**: Confirm Resource Group name and verify Arc server registration

**Issue**: "Azure CLI authentication required"
**Solution**: Run `az login` and `az account set --subscription "your-subscription"`

**Issue**: "Extension update failures"
**Solution**: Check Arc server connectivity and Azure Arc agent status

### Debug Mode

```powershell
# Enable detailed debugging
$DebugPreference = "Continue"
$VerbosePreference = "Continue"
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "ArcRG" -Verbose -Debug

# PowerShell execution policy issues
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Logging and Monitoring

```powershell
# Redirect output to log file for analysis
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "ArcRG" -Verbose > "ArcExtensions-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" 2>&1
```

## ?? Contributing

We welcome contributions to improve Azure Arc extension management capabilities!

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/arc-enhancement`)
3. **Follow** PowerShell best practices and Azure coding standards
4. **Add** comprehensive help documentation and examples
5. **Test** thoroughly with multiple Resource Groups and Arc server configurations
6. **Update** this README for any new functionality
7. **Commit** with clear, descriptive messages following conventional commits
8. **Submit** a pull request with detailed description of changes

### Development Standards

- Follow PowerShell Script Analyzer guidelines and best practices
- Include comprehensive error handling for Azure API operations
- Add appropriate verbose output and progress indicators
- Maintain compatibility with PowerShell 5.1 and 7+
- Document all parameters with detailed help and examples
- Test with both small and large-scale Arc deployments

### Testing Guidelines

- Test with various Azure Arc server configurations
- Validate against different extension types and versions
- Verify operation in different Azure regions and subscriptions
- Test both report and upgrade modes extensively
- Validate error handling and recovery scenarios

## ?? License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## ?? Disclaimer

This code is provided for demonstration purposes only. It is intended to illustrate Azure Arc extension management concepts and should not be used in production environments without proper review, testing, and validation. The authors and distributors of this code make no warranties regarding its functionality, security, or suitability for any specific use. Use at your own risk.

**Production Deployment Recommendations**:

- Thoroughly test in development environments before production use
- Implement appropriate backup and rollback procedures
- Monitor extension updates for potential impact on workloads
- Follow your organization's change management processes
- Maintain audit logs of all extension management activities

## ?? Contact

For questions, feedback, or support regarding Azure Arc extension management:

- **Email**: [GitHub@ffournier.ca](mailto:GitHub@ffournier.ca)
- **GitHub**: [@Frafou](https://github.com/Frafou)
- **Issues**: Use GitHub Issues for bug reports and feature requests

## ??? Tags

`PowerShell` `Azure Arc` `Hybrid Cloud` `Extension Management` `Azure CLI` `Infrastructure Management` `DevOps` `Automation` `Enterprise` `Cloud Operations`
