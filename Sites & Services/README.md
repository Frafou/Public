# Set-ChangeNotification Script

## Overview

The **Set-ChangeNotification.ps1** script is an Active Directory replication optimization tool that enables change notification for AD site links. This PowerShell script helps improve replication performance by configuring immediate replication notifications instead of relying solely on scheduled replication intervals.

## Purpose

In multi-site Active Directory environments, replication typically occurs based on scheduled intervals. Change notification allows for immediate replication when changes occur, reducing latency and improving consistency across sites. This is particularly beneficial in environments where timely replication is critical for business operations.

## Features

### ? **Flexible Operation Modes**
- **All Site Links**: Process every site link in the forest automatically
- **Targeted Site Link**: Process a specific site link by name
- **Safe Testing**: Built-in `-WhatIf` support for previewing changes

### ? **Robust Error Handling**
- Comprehensive input validation
- Detailed error messages with troubleshooting guidance
- Graceful handling of permission and connectivity issues

### ? **Enterprise-Ready**
- PowerShell comment-based help documentation
- Verbose logging for troubleshooting
- Supports common PowerShell parameters
- Color-coded output for easy status identification

## Requirements

### System Prerequisites
- **PowerShell**: 5.1 or higher
- **Operating System**: Windows Server 2016+ or Windows 10+ with RSAT
- **Execution Policy**: RemoteSigned or Unrestricted

### Active Directory Requirements
- **Permissions**: Domain Administrator or delegated site management permissions
- **Network**: Connectivity to domain controllers
- **Module**: Active Directory PowerShell module (RSAT)

### Installation Commands
```powershell
# Install RSAT Active Directory module (Windows 10/11)
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online

# Verify module availability
Get-Module ActiveDirectory -ListAvailable

# Import module
Import-Module ActiveDirectory
```

## Usage Examples

### Basic Operations
```powershell
# Enable change notification for ALL site links in the forest
.\Set-ChangeNotification.ps1

# Enable change notification for a specific site link
.\Set-ChangeNotification.ps1 -SiteLinkName "DEFAULTIPSITELINK"
```

### Safe Testing (Recommended)
```powershell
# Preview changes without making any modifications (ALWAYS RUN FIRST)
.\Set-ChangeNotification.ps1 -WhatIf

# Preview changes for a specific site link
.\Set-ChangeNotification.ps1 -SiteLinkName "MySiteLink" -WhatIf
```

### Advanced Operations
```powershell
# Enable with detailed verbose output for troubleshooting
.\Set-ChangeNotification.ps1 -Verbose

# Interactive confirmation for each change
.\Set-ChangeNotification.ps1 -Confirm

# Combine parameters for comprehensive testing
.\Set-ChangeNotification.ps1 -SiteLinkName "DEFAULTIPSITELINK" -WhatIf -Verbose
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `SiteLinkName` | String | No | None | Name of specific site link to process. If omitted, all site links are processed. |

### Common Parameters Supported
- `-WhatIf`: Preview operations without making changes
- `-Verbose`: Enable detailed output logging
- `-Confirm`: Interactive confirmation before each operation

## Technical Implementation

### What the Script Does

1. **Module Validation**: Imports and validates Active Directory PowerShell module
2. **Site Link Discovery**: 
   - If `SiteLinkName` specified: Retrieves that specific site link
   - If no parameter: Retrieves all site links in the forest
3. **Options Analysis**: Examines current Options attribute values
4. **Change Notification Setup**: Sets bit 1 (change notification flag)
5. **Status Reporting**: Provides detailed feedback on changes made

### Options Attribute Behavior

The script modifies the `Options` attribute of AD replication site links:
- **Bit 1 (Value 1)**: Change notification flag
- **Current Implementation**: Sets Options to 1 (replaces existing value)
- **Code Comments**: Mention bitwise OR preservation, but actual implementation replaces value

### Replication Impact

**Benefits:**
- Immediate replication when changes occur
- Reduced replication latency across sites
- Improved data consistency
- Better user experience in multi-site environments

**Considerations:**
- May increase network traffic between sites
- Best suited for well-connected sites with adequate bandwidth
- Requires monitoring of network performance after implementation

## Output Examples

### Successful Execution
```
========================================
Script completed successfully.
Importing Active Directory module.
Active Directory module imported successfully.
Retrieving site links from Active Directory.
Change notification enabled for site link 'DEFAULTIPSITELINK'.
Options value changed from 0 to 1
Script completed successfully.
```

### WhatIf Preview
```
What if: Performing the operation "Set-ADReplicationSiteLink" on target "DEFAULTIPSITELINK".
```

### Verbose Output
```
VERBOSE: Found 2 site link(s)
VERBOSE: Processing site link: DEFAULTIPSITELINK
VERBOSE: Current Options value: 0
VERBOSE: New Options value: 1
```

## Error Handling & Troubleshooting

### Common Issues

| Error Condition | Cause | Resolution |
|----------------|-------|------------|
| Module not found | RSAT not installed | Install Active Directory PowerShell module |
| Access denied | Insufficient permissions | Run as Domain Administrator |
| Site link not found | Invalid site link name | Verify site link exists with `Get-ADReplicationSiteLink` |
| Network connectivity | DC unreachable | Check network connectivity and DNS resolution |

### Validation Commands

```powershell
# Check current site link configuration
Get-ADReplicationSiteLink -Filter * | Select-Object Name, Options, Cost, ReplicationFrequencyInMinutes

# Verify specific site link exists
Get-ADReplicationSiteLink -Identity "DEFAULTIPSITELINK"

# Test Active Directory connectivity
Test-NetConnection -ComputerName $env:LOGONSERVER -Port 389

# Verify current user permissions
whoami /groups | findstr "Domain Admins"
```

## Best Practices

### Pre-Implementation
1. **Test in Lab Environment**: Always test in non-production environment first
2. **Use WhatIf Parameter**: Preview all changes before execution
3. **Document Current State**: Export current site link configurations
4. **Network Assessment**: Ensure adequate bandwidth for increased replication traffic

### Implementation Strategy
1. **Staged Rollout**: Consider enabling one site link at a time initially
2. **Monitor Replication Health**: Use `repadmin` tools to monitor replication status
3. **Performance Monitoring**: Watch network utilization and replication latency

### Post-Implementation
1. **Verify Configuration**: Confirm Options values are correctly set
2. **Monitor Performance**: Track replication performance and network impact
3. **Document Changes**: Update network and AD documentation

## Monitoring & Validation

### Replication Health Checks
```powershell
# Check replication summary
repadmin /replsummary

# View replication partners
repadmin /showrepl

# Monitor replication queue
repadmin /queue
```

### Performance Monitoring
- Monitor network bandwidth utilization between sites
- Track replication latency using `repadmin` tools
- Check Windows Event Logs for replication events (Event IDs 1394, 1988, etc.)
- Use Performance Monitor counters for DFS Replication metrics

## Version Information

- **Current Version**: 1.1.0
- **Created**: December 2, 2025
- **Last Updated**: December 2, 2025
- **License**: MIT

### Version History
- **v1.0**: Initial release with basic functionality
- **v1.1**: Added SiteLinkName parameter for targeted site link processing

## Known Issues

?? **Note**: The script contains a potential issue where it references `$SiteLinkName` in the `Set-ADReplicationSiteLink` command instead of `$siteLink.Name`, which may cause issues when processing all site links without specifying a name parameter.

## Support

### Getting Help
```powershell
# View full script help
Get-Help .\Set-ChangeNotification.ps1 -Full

# View examples only
Get-Help .\Set-ChangeNotification.ps1 -Examples

# View parameter help
Get-Help .\Set-ChangeNotification.ps1 -Parameter SiteLinkName
```

### Additional Resources
- [Active Directory Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/)
- [Understanding AD Site Topology](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology)
- [PowerShell Active Directory Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/)

## Disclaimer

This script is provided as sample code for demonstration and educational purposes. Always test thoroughly in a lab environment before using in production. The script modifies Active Directory replication settings which can impact network performance and data consistency across your organization.

---

**?? Important**: Always run with `-WhatIf` parameter first to preview changes before making any modifications to your Active Directory environment.