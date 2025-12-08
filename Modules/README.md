# PowerShell Module Update Script

A comprehensive PowerShell script for automating module updates from the PowerShell Gallery with enterprise-grade features and security considerations.

## ?? Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Security](#security)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## ?? Overview

The Update-Modules.ps1 script provides enterprise-ready automation for PowerShell module lifecycle management. It automatically checks for module updates, installs the latest versions, and cleans up old versions to maintain a streamlined PowerShell environment.

### Key Benefits

- **Automated Updates**: Automatically updates all installed PowerShell modules to their latest versions
- **Version Management**: Removes outdated module versions to prevent conflicts
- **Enterprise Ready**: Supports automation, compliance, and audit requirements
- **Cross-Platform**: Compatible with Windows PowerShell and PowerShell Core
- **Secure Execution**: Implements proper elevation and security validation

## ? Features

### Module Management
- ? Scans all installed PowerShell modules for available updates
- ? Compares local versions with PowerShell Gallery latest versions
- ? Supports both Windows PowerShell and PowerShell Core editions
- ? Automatic cleanup of old module versions after updates
- ? Progress feedback and detailed status reporting

### Administrative Functions
- ? Automatic elevation to administrator privileges when required
- ? Support for PowerShell ISE, Console, and PowerShell Core
- ? Cross-platform PowerShell edition detection and handling
- ? Comprehensive error handling and logging

### Enterprise Features
- ? Audit trail for compliance and governance
- ? Integration with enterprise automation systems
- ? Performance optimization for bulk operations
- ? Network bandwidth consideration for large downloads

## ?? Prerequisites

### System Requirements
- **PowerShell Version**: 5.1 or higher
- **Operating System**: Windows 10/11, Windows Server 2016+, or any OS supporting PowerShell Core
- **Privileges**: Local administrator rights
- **Network**: Internet connectivity to PowerShell Gallery

### Required Modules
- **PowerShellGet** (for Find-Module, Install-Module, Update-Module)
- **PackageManagement** (dependency for PowerShellGet)

### Execution Policy
```powershell
# Set execution policy to allow script execution
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## ?? Installation

1. **Download the Script**
   ```bash
   git clone https://github.com/your-org/powershell-modules.git
   cd powershell-modules/Modules
   ```

2. **Verify Script Integrity**
   ```powershell
   Get-FileHash .\Update-Modules.ps1
   ```

3. **Set Execution Policy** (if needed)
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## ?? Usage

### Basic Usage

```powershell
# Update all PowerShell modules (requires administrator privileges)
.\Update-Modules.ps1
```

### Advanced Usage

```powershell
# Check administrator status only
Invoke-ElevatedExecution -Check

# Run with whatif to preview changes
.\Update-Modules.ps1 -WhatIf

# Run with verbose output for detailed logging
.\Update-Modules.ps1 -Verbose
```

### Automated Execution

**Windows Task Scheduler:**
```xml
<Command>powershell.exe</Command>
<Arguments>-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Update-Modules.ps1"</Arguments>
```

**Scheduled Task PowerShell:**
```powershell
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Update-Modules.ps1"'
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2AM
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "PowerShell Module Updates" -Description "Weekly PowerShell module updates"
```

## ?? Security

### Security Features
- **Privilege Validation**: Requires and validates administrator privileges
- **Secure Sources**: Only downloads from trusted PowerShell Gallery
- **Digital Signatures**: Validates module digital signatures
- **Secure Elevation**: Implements proper UAC elevation procedures

### Security Best Practices
- Always run from trusted locations
- Verify script integrity before execution
- Review update logs for unexpected changes
- Test updates in non-production environments first

## ?? Best Practices

### Development Environment
1. **Test First**: Always test module updates in development before production
2. **Version Control**: Track module versions and changes
3. **Dependency Mapping**: Document module dependencies and compatibility

### Production Environment
1. **Change Management**: Integrate with your change management process
2. **Backup Strategy**: Backup system state before major module updates
3. **Rollback Plan**: Maintain ability to rollback problematic updates
4. **Monitoring**: Monitor systems after module updates for issues

### Maintenance Schedule
- **Weekly Updates**: For development environments
- **Monthly Updates**: For production environments (after testing)
- **Emergency Updates**: For security-critical module updates

## ?? Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Execution Policy Error | PowerShell execution policy restrictions | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Access Denied | Insufficient privileges | Run PowerShell as Administrator |
| Network Errors | Cannot reach PowerShell Gallery | Check internet connectivity and proxy settings |
| Module Conflicts | Multiple module versions installed | Run script to clean up old versions |

### Debug Mode
```powershell
# Enable verbose logging for troubleshooting
.\Update-Modules.ps1 -Verbose -Debug
```

### Log Analysis
```powershell
# View recent log entries
Get-Content ".\Update-Modules-$(Get-Date -Format 'yyyy-MM-dd').log" | Select-Object -Last 20
```

## ?? Monitoring and Reporting

### Log Files
- **Location**: Same directory as script
- **Format**: `Update-Modules-YYYY-MM-DD.log`
- **Content**: Detailed execution logs with timestamps

### Performance Metrics
- Execution time per module
- Network bandwidth utilization
- Success/failure rates
- System resource usage

## ?? Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Code Standards
- Follow PowerShell best practices
- Include comment-based help for functions
- Add appropriate error handling
- Update documentation for changes

## ?? License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ?? Support

- **Documentation**: See inline help with `Get-Help .\Update-Modules.ps1 -Full`
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Community**: Join our PowerShell community discussions

## ?? Related Resources

- [PowerShell Gallery](https://www.powershellgallery.com/)
- [PowerShellGet Module Documentation](https://docs.microsoft.com/en-us/powershell/module/powershellget/)
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/security/)
- [Enterprise PowerShell Management](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/)

---

**Last Updated**: December 8, 2025  
**Version**: 1.0  
**Maintainer**: PowerShell Team