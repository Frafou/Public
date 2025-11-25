# Managed Service Account (MSA) Management Scripts

A comprehensive PowerShell toolkit for implementing, managing, and maintaining Managed Service Accounts (MSA) and Group Managed Service Accounts (gMSA) in Active Directory environments, including automated scheduled task migration and configuration.

## ?? Scripts Overview

### Install-sMSA_ADAccount.ps1

**Purpose**: Standalone Managed Service Account (sMSA) lifecycle management for single-server applications

**Key Features**:

- **Automated sMSA Creation**: Creates new standalone managed service accounts with proper configuration
- **Privilege Assignment**: Configures appropriate service account privileges and permissions
- **Installation Validation**: Verifies successful account installation on target servers
- **Security Assessment**: Validates account security settings and compliance requirements
- **Interactive Management**: Guided setup for complex sMSA deployment scenarios

**Use Cases**:

- Single-server application service accounts
- Legacy application service account migration
- Development and testing environment MSA implementation
- Isolated service account requirements

### Install-gMSA_ADAccount.ps1

**Purpose**: Group Managed Service Account (gMSA) deployment for multi-server environments and scale-out applications

**Key Features**:

- **gMSA Account Creation**: Creates group managed service accounts with automatic password management
- **Multi-Server Support**: Configures accounts for use across multiple domain-joined servers
- **KDS Root Key Management**: Validates and configures Key Distribution Services prerequisites
- **Principal Group Management**: Manages authorized host groups for gMSA access
- **Enterprise Integration**: Supports large-scale enterprise gMSA deployments

**Use Cases**:

- Multi-server application clusters
- Load-balanced web applications
- High-availability database services
- Enterprise service account standardization

### Update-ScheduledTaskToMSA.ps1

**Purpose**: Automated migration of existing scheduled tasks to use Managed Service Account authentication

**Key Features**:

- **Task Discovery**: Identifies scheduled tasks requiring MSA conversion
- **Automated Migration**: Updates task credentials to use MSA authentication
- **Validation Testing**: Verifies successful task migration and execution capabilities
- **Rollback Support**: Provides rollback capabilities for failed migrations
- **Bulk Operations**: Supports migration of multiple tasks across servers

**Use Cases**:

- Legacy scheduled task modernization
- Security compliance initiatives
- Service account consolidation projects
- Automated maintenance task updates

### Update-TaskSchedule.ps1

**Purpose**: OMS/SCOM scheduled task management with interactive selection and MSA integration

**Key Features**:

- **Interactive Task Selection**: GUI-based task selection using Out-GridView
- **Schedule Modification**: Updates task timing, triggers, and execution parameters
- **MSA Integration**: Configures tasks to use Managed Service Account credentials
- **Monitoring Integration**: Supports OMS (Operations Management Suite) and SCOM integration
- **Enterprise Scheduling**: Manages complex enterprise task scheduling scenarios

**Use Cases**:

- Operations monitoring task management
- Enterprise monitoring system integration
- Automated maintenance window scheduling
- System Center Operations Manager task configuration

## ?? Quick Start

### Prerequisites

- **Active Directory Environment**: Windows Server 2012 R2 or higher domain functional level
- **PowerShell**: Version 5.1 minimum (PowerShell 7+ recommended)
- **Administrative Privileges**: Domain Administrator or equivalent MSA management permissions
- **KDS Root Key**: Required for gMSA operations (Windows Server 2012+ domains)
- **Modules**: ActiveDirectory and ScheduledTasks PowerShell modules

### Installation

```powershell
# Install required PowerShell modules
Install-Module ActiveDirectory -Force
Install-Module ScheduledTasks -Force

# Verify domain functional level (required for MSA support)
Get-ADDomain | Select-Object DomainMode

# Check KDS Root Key existence (required for gMSA)
Get-KdsRootKey

# Create KDS Root Key if needed (gMSA requirement)
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

### Authentication Setup

```powershell
# Verify Active Directory connectivity
Get-ADDomain

# Ensure proper permissions for MSA management
# Required roles:
# - Account Operators (minimum)
# - Domain Admins (recommended for full functionality)

# Verify scheduled task management permissions
Get-ScheduledTask | Select-Object -First 5
```

### Basic Usage

```powershell
# Create standalone Managed Service Account
.\Install-sMSA_ADAccount.ps1

# Create Group Managed Service Account
.\Install-gMSA_ADAccount.ps1

# Migrate existing scheduled tasks to MSA
.\Update-ScheduledTaskToMSA.ps1

# Interactive scheduled task management
.\Update-TaskSchedule.ps1

# Run with verbose output for detailed logging
.\Install-gMSA_ADAccount.ps1 -Verbose
```

## ?? Use Cases

### 1. Enterprise Security Modernization

- **Legacy Account Migration**: Replace traditional service accounts with managed alternatives
- **Password Management Elimination**: Implement automatic password rotation for service accounts
- **Security Compliance**: Meet enterprise security standards for service account management
- **Audit Trail Generation**: Maintain comprehensive logs of service account activities

### 2. Application Service Account Management

- **Single-Server Applications**: Deploy sMSA for isolated application requirements
- **Multi-Server Applications**: Implement gMSA for clustered and load-balanced applications
- **Database Services**: Secure database service accounts with automatic password management
- **Web Application Security**: Enhance web application security with managed service accounts

### 3. Scheduled Task Modernization

- **Legacy Task Updates**: Modernize existing scheduled tasks with MSA authentication
- **Maintenance Automation**: Secure automated maintenance tasks with managed accounts
- **Monitoring Integration**: Integrate monitoring systems with MSA-secured scheduled tasks
- **Compliance Reporting**: Generate compliance reports for scheduled task security

### 4. Operations Management Integration

- **SCOM Integration**: Configure System Center Operations Manager with MSA authentication
- **OMS Connectivity**: Secure Operations Management Suite connections with managed accounts
- **Monitoring Task Security**: Implement secure authentication for monitoring and alerting tasks
- **Enterprise Scheduling**: Manage complex enterprise scheduling requirements

## ?? Features

### Advanced Account Management

- **Automated Account Creation**: Streamlined MSA and gMSA creation with validation
- **Security Configuration**: Proper privilege assignment and security settings
- **Multi-Environment Support**: Development, testing, and production environment compatibility
- **Scalable Deployment**: Support for large-scale enterprise MSA implementations

### Comprehensive Task Migration

- **Legacy Compatibility**: Supports migration from traditional service account configurations
- **Validation Testing**: Comprehensive testing of migrated task functionality
- **Rollback Capabilities**: Safe rollback options for failed migrations
- **Bulk Processing**: Efficient processing of multiple tasks and servers

### Enterprise Integration

- **Active Directory Integration**: Deep integration with Active Directory services
- **Group Policy Support**: Compatible with Group Policy-based configurations
- **Monitoring System Integration**: Native support for enterprise monitoring solutions
- **Audit and Compliance**: Comprehensive logging for security and compliance requirements

### Interactive Management

- **GUI-Based Selection**: User-friendly interfaces for complex task management
- **Validation Workflows**: Step-by-step validation of account and task configurations
- **Progress Tracking**: Real-time progress monitoring for long-running operations
- **Error Handling**: Robust error handling with detailed diagnostic information

## ?? Requirements

### Active Directory Requirements

- **Domain Functional Level**: Windows Server 2012 R2 minimum (Windows Server 2016+ recommended)
- **Forest Functional Level**: Windows Server 2012 R2 minimum for full gMSA support
- **Domain Controllers**: At least one Windows Server 2012+ domain controller
- **KDS Root Key**: Required for gMSA operations (auto-created by scripts if needed)

### System Requirements

- **PowerShell**: Version 5.1 minimum (PowerShell 7+ recommended for enhanced performance)
- **Operating System**: Windows 10/11, Windows Server 2012 R2 or higher
- **Memory**: 4GB RAM minimum for large-scale operations
- **Network**: Stable connectivity to Active Directory domain controllers

### Permissions Required

- **Domain Level**:
  - Account Operators (minimum for basic MSA operations)
  - Domain Admins (recommended for full functionality)
  - Enterprise Admins (required for cross-domain gMSA operations)

- **Server Level**:
  - Local Administrator (for scheduled task management)
  - "Log on as a service" right (for MSA installation)
  - "Act as part of the operating system" (for advanced MSA operations)

### Module Dependencies

```powershell
# Required PowerShell modules
ActiveDirectory >= 1.0.0
ScheduledTasks >= 1.0.0
Microsoft.PowerShell.Security >= 1.0.0

# Optional but recommended
PSLogging >= 2.5.0 (for enhanced logging)
ImportExcel >= 7.0.0 (for report generation)
```

## ?? Advanced Configuration

### KDS Root Key Management

```powershell
# Check existing KDS Root Key
Get-KdsRootKey

# Create new KDS Root Key (requires Enterprise Admin)
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# Test KDS Root Key functionality
Test-KdsRootKey -KeyId (Get-KdsRootKey)[0].KeyId
```

### Group Managed Service Account Configuration

```powershell
# Create security group for gMSA authorization
New-ADGroup -Name "gMSA-WebServers" -GroupScope DomainLocal -GroupCategory Security

# Add servers to authorization group
Add-ADGroupMember -Identity "gMSA-WebServers" -Members "WebServer01$", "WebServer02$"

# Create gMSA with specific configuration
.\Install-gMSA_ADAccount.ps1 -ServiceAccountName "WebApp-gMSA" -AuthorizedHosts "gMSA-WebServers"
```

### Scheduled Task Migration Automation

```powershell
# Mass migration of scheduled tasks
$tasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -like "*service*" }
foreach ($task in $tasks) {
    .\Update-ScheduledTaskToMSA.ps1 -TaskName $task.TaskName -MSAName "MyApp-sMSA$"
}
```

### Custom Logging Configuration

```powershell
# Enable detailed logging for all MSA operations
$LogPath = "C:\Logs\MSA-Operations"
New-Item -ItemType Directory -Path $LogPath -Force

# Configure logging for all scripts
$env:MSA_LOG_PATH = $LogPath
$env:MSA_LOG_LEVEL = "Verbose"
```

## ?? Troubleshooting

### Common Issues

**Issue**: "KDS Root Key not found" error for gMSA operations
**Solution**: Create KDS Root Key with `Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))`

**Issue**: "Access denied" when creating MSA accounts
**Solution**: Verify Domain Administrator privileges and Active Directory connectivity

**Issue**: "Scheduled task update failed" errors
**Solution**: Ensure Local Administrator rights and verify task exists and is accessible

**Issue**: "MSA account installation failed on target server"
**Solution**: Verify server domain membership and restart target server if necessary

**Issue**: "Group membership errors for gMSA authorization"
**Solution**: Verify computer accounts are properly added to authorization groups

### Debug Mode

```powershell
# Enable comprehensive debugging for MSA operations
$DebugPreference = "Continue"
$VerbosePreference = "Continue"

# Run scripts with full diagnostic output
.\Install-gMSA_ADAccount.ps1 -Debug -Verbose

# Enable Active Directory module debugging
$env:ADPS_LoadDefaultDrive = 0
Import-Module ActiveDirectory -Verbose
```

### Performance Optimization

```powershell
# Optimize for large-scale operations
$env:MSA_BATCH_SIZE = 50          # Process tasks in batches
$env:MSA_PARALLEL_JOBS = 8        # Number of parallel operations
$env:MSA_TIMEOUT_SECONDS = 300    # Operation timeout
```

## ?? Contributing

We welcome contributions to improve Managed Service Account management capabilities!

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/msa-enhancement`)
3. **Follow** PowerShell best practices and Active Directory security standards
4. **Add** comprehensive testing with various AD environments
5. **Test** thoroughly with different domain functional levels and configurations
6. **Update** documentation for any new functionality
7. **Commit** with clear, descriptive messages following conventional commits
8. **Submit** a pull request with detailed description and testing results

### Development Standards

- Follow PowerShell Script Analyzer guidelines and security best practices
- Include comprehensive error handling for Active Directory operations
- Add appropriate progress indicators for long-running MSA operations
- Maintain compatibility with various Active Directory versions
- Document all parameters with detailed help and examples
- Test with both small and large-scale Active Directory environments

### Testing Guidelines

- Test with various Active Directory domain and forest functional levels
- Validate MSA operations across different server operating systems
- Verify scheduled task migration with various task types and configurations
- Test error handling and recovery scenarios for failed operations
- Validate cross-domain gMSA operations in complex AD topologies

## ?? License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## ?? Disclaimer

This code is provided for demonstration purposes only. It is intended to illustrate Managed Service Account management concepts and should not be used in production environments without proper review, testing, and validation. The authors and distributors of this code make no warranties regarding its functionality, security, or suitability for any specific use. Use at your own risk.

**Production Deployment Recommendations**:

- Test thoroughly in isolated Active Directory environments before production deployment
- Implement appropriate backup procedures for Active Directory objects
- Follow organization change management processes for service account modifications
- Monitor MSA account usage and access patterns after deployment
- Maintain documentation of all MSA implementations and dependencies

## ?? Contact

For questions, feedback, or support regarding Managed Service Account management:

- **Email**: [GitHub@ffournier.ca](mailto:GitHub@ffournier.ca)
- **GitHub**: [@Frafou](https://github.com/Frafou)
- **Issues**: Use GitHub Issues for bug reports and feature requests

## ??? Tags

`PowerShell` `Active Directory` `Managed Service Accounts` `gMSA` `sMSA` `Scheduled Tasks` `Enterprise Security` `Service Account Management` `Windows Server` `Automation`
