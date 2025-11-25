# DNS Management Scripts

A collection of PowerShell scripts for DNS infrastructure management, focusing on DNS scavenging configuration auditing and reporting across Active Directory environments.

## ?? Scripts Overview

### GET-DNSScavengingData.ps1

**Purpose**: Comprehensive DNS scavenging configuration auditing and monitoring across Domain Controllers

**Key Features**:

- Automated discovery of all Domain Controllers in the domain
- Detailed collection of DNS scavenging settings from each DC
- Advanced logging capabilities using PSLogging module
- Performance metrics and execution timing
- Comprehensive error handling and progress tracking
- Color-coded console output for easy monitoring

**What it collects**:

- Scavenging intervals and states
- Last scavenging timestamps
- Refresh and no-refresh intervals
- Domain Controller availability status

### GET-DNSScavengingData(DNS).ps1

**Purpose**: Enhanced DNS scavenging configuration auditing with zone-based DNS server discovery

**Key Features**:

- Automated DNS server discovery through NS records and zone analysis
- Zone-specific scavenging configuration collection
- Advanced error handling with detailed logging capabilities
- Whatif parameter support for analysis mode
- Comprehensive audit trail generation
- Performance timing and execution metrics

**What it collects**:

- DNS server identification through zone NS records
- Scavenging intervals and current states
- Last scavenging operation timestamps
- Refresh and no-refresh interval configurations
- Zone-specific DNS server configurations

### PowerShell Script for DNS Scavenging Report.ps1

**Purpose**: DNS scavenging configuration reporting and analysis

**Key Features**:

- Cross-domain controller scavenging configuration comparison
- CSV export for compliance reporting and analysis
- Automated detection of configuration inconsistencies
- Comprehensive scavenging status overview
- Multi-domain controller environment support

**Output**:

- Detailed CSV reports with scavenging configuration data
- Console-based status reporting
- Configuration comparison matrices

## ?? Quick Start

### Prerequisites

- Windows PowerShell 5.1+ or PowerShell 7+
- Administrative privileges on Domain Controllers
- Active Directory PowerShell module
- PSLogging module (for enhanced logging features)
- Network connectivity to all Domain Controllers
- Appropriate Active Directory permissions

### Installation

```powershell
# Install required modules (run as administrator)
Install-Module ActiveDirectory -Force
Install-Module PSLogging -Force

# Verify Domain Controller connectivity
Get-ADDomainController -Filter *
```

### Basic Usage

```powershell
# Collect DNS scavenging data with detailed logging (Domain Controller method)
.\GET-DNSScavengingData.ps1

# Enhanced DNS scavenging data collection (Zone/NS record method)
.\GET-DNSScavengingData\(DNS\).ps1

# Run enhanced script with analysis mode
.\GET-DNSScavengingData\(DNS\).ps1 -Whatif

# Run with verbose output for troubleshooting
.\GET-DNSScavengingData.ps1 -Verbose

# Generate comprehensive scavenging report
.\"PowerShell Script for DNS Scavenging Report.ps1"
```

## ?? Script Comparison

| Feature | GET-DNSScavengingData.ps1 | GET-DNSScavengingData(DNS).ps1 | PowerShell Script for DNS Scavenging Report.ps1 |
|---------|---------------------------|--------------------------------|--------------------------------------------------|
| **Discovery Method** | Domain Controller enumeration | Zone NS record analysis | Variable (depends on implementation) |
| **Target Servers** | All Domain Controllers | DNS servers from NS records | Configurable DNS servers |
| **Whatif Support** | No | Yes (-Whatif parameter) | Variable |
| **Logging Method** | PSLogging module | PSLogging module | Standard PowerShell |
| **Output Format** | Console + Log files | Console + Log files | CSV + Console |
| **Best Use Case** | DC-focused DNS auditing | Zone-focused DNS analysis | Compliance reporting |
| **Enterprise Ready** | Yes | Yes | Yes |

### When to Use Which Script

- **GET-DNSScavengingData.ps1**: Use when you need to audit DNS scavenging settings specifically on Domain Controllers
- **GET-DNSScavengingData(DNS).ps1**: Use when you need zone-based DNS server discovery with analysis mode support
- **PowerShell Script for DNS Scavenging Report.ps1**: Use when you need formatted reports for compliance and documentation

## ?? Use Cases

### 1. DNS Infrastructure Auditing

- Regular assessment of DNS scavenging configurations
- Compliance reporting for DNS management policies
- Infrastructure health monitoring and validation

### 2. Configuration Consistency Monitoring

- Identify mismatched scavenging settings across DCs
- Validate scavenging policy implementation
- Detect configuration drift over time

### 3. Troubleshooting DNS Issues

- Analyze scavenging-related DNS problems
- Verify proper scavenging intervals and timing
- Investigate stale DNS record issues

### 4. Change Management Support

- Before/after comparison of DNS configuration changes
- Impact assessment for DNS policy modifications
- Documentation for change control processes

## ?? Features

### Advanced Logging

- Timestamped execution logs
- Multiple log levels (INFO, WARNING, ERROR, DEBUG)
- Color-coded console output
- Performance timing and metrics

### Comprehensive Reporting

- CSV export capabilities
- Detailed configuration matrices
- Cross-DC comparison views
- Executive summary reports

### Enterprise Ready

- Multi-domain controller support
- Bulk operations across large environments
- Network storage compatibility
- Automated error recovery

### Security & Compliance

- No credential storage or hardcoding
- Audit trail generation
- Read-only operations (no configuration changes)
- Principle of least privilege support

## ?? Requirements

### System Requirements

- Windows Server 2012 R2 or higher (for target DCs)
- PowerShell 5.1 minimum (PowerShell 7+ recommended)
- .NET Framework 4.7.2 or higher

### Active Directory Requirements

- Domain functional level Windows Server 2008 R2 or higher
- DNS Server role installed on Domain Controllers
- Active Directory Web Services (ADWS) running
- Proper DNS resolution within the domain

### Permissions Required

- **Domain Users** (minimum for basic queries)
- **DNS Administrators** (recommended for full access)
- **Domain Admins** (for comprehensive auditing)
- Local administrative rights on execution system

### Network Requirements

- TCP/IP connectivity to all Domain Controllers
- DNS resolution to Domain Controller FQDNs
- Required ports: 389 (LDAP), 636 (LDAPS), 53 (DNS)

## ?? Documentation

### Getting Help

```powershell
# View comprehensive help for each script
Get-Help .\GET-DNSScavengingData.ps1 -Full
Get-Help .\"PowerShell Script for DNS Scavenging Report.ps1" -Full

# View examples
Get-Help .\GET-DNSScavengingData.ps1 -Examples

# View specific parameter information
Get-Help .\GET-DNSScavengingData.ps1 -Parameter Verbose
```

### Output Files

- **Log Files**: `[ScriptName]-YYYYMMDD-HHMMSS.log`
- **CSV Reports**: `DNS_Scavenging_Report.csv`
- **Location**: Script execution directory

## ??? Advanced Configuration

### Custom Logging

```powershell
# Configure custom log levels and paths
$LogPath = "C:\DNSAudit\Logs"
.\GET-DNSScavengingData.ps1 -LogPath $LogPath -Verbose
```

### Automated Scheduling

```powershell
# Create scheduled task for regular DNS auditing
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\GET-DNSScavengingData.ps1"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6:00AM
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "DNS Scavenging Audit"
```

## ?? Troubleshooting

### Common Issues

**Issue**: Module import errors
**Solution**: Ensure Active Directory and PSLogging modules are installed

**Issue**: Access denied errors
**Solution**: Verify account permissions and administrative rights

**Issue**: Domain Controller connectivity issues
**Solution**: Check network connectivity and DNS resolution

**Issue**: Script execution policy restrictions
**Solution**: Configure appropriate PowerShell execution policy

### Debug Mode

```powershell
# Enable detailed debugging output
$DebugPreference = "Continue"
.\GET-DNSScavengingData.ps1 -Debug
```

## ?? Contributing

We welcome contributions to improve these DNS management scripts!

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/dns-enhancement`)
3. **Follow** PowerShell best practices and coding standards
4. **Add** comprehensive help documentation
5. **Test** thoroughly in lab environments
6. **Update** this README if adding new functionality
7. **Commit** with clear, descriptive messages
8. **Submit** a pull request with detailed description

### Development Standards

- Follow PowerShell Script Analyzer guidelines
- Include comprehensive error handling
- Add appropriate verbose and debug output
- Maintain backward compatibility where possible
- Document all parameters and examples

## ?? License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## ?? Disclaimer

This code is provided for demonstration purposes only. It is intended to illustrate concepts and should not be used in production environments without proper review, testing, and validation. The authors and distributors of this code make no warranties regarding its functionality, security, or suitability for any specific use. Use at your own risk.

Always test scripts in a lab environment before deploying to production DNS infrastructure.

## ?? Contact

For questions, feedback, or support regarding these DNS management scripts:

- **Email**: <GitHub@ffournier.ca>
- **GitHub**: [@Frafou](https://github.com/Frafou)
- **Issues**: Use GitHub Issues for bug reports and feature requests

## ??? Tags

`PowerShell` `DNS` `Active Directory` `Scavenging` `Domain Controllers` `Infrastructure Monitoring` `Windows Server` `Network Administration` `System Administration` `Compliance Auditing`
