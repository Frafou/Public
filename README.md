# PowerShell Scripts Collection

A comprehensive collection of enterprise-grade PowerShell scripts for Windows administration, Azure management, Active Directory operations, and media processing.

## ?? Repository Structure

### ?? Azure Extensions Management

**Location**: `Azure-Extensions/`

- **`Manage-AzureArcExtensions.ps1`** - Manages Azure Arc-enabled server extensions
  - Reports outdated extensions across resource groups
  - Automated bulk extension updates
  - Comprehensive logging and CSV reporting
  - Supports both Azure CLI and Az.ConnectedMachine module

### ?? DNS Management

**Location**: `DNS/`

- **`GET-DNSScavengingData.ps1`** - DNS scavenging configuration auditing
  - Collects DNS scavenging settings from all Domain Controllers
  - Comprehensive logging with PSLogging module
  - Performance metrics and execution timing

- **`PowerShell Script for DNS Scavenging Report.ps1`** - DNS scavenging reporting
  - Generates comprehensive DNS scavenging reports
  - CSV export for compliance and analysis
  - Multi-domain controller support

### ?? Managed Service Accounts (MSA)

**Location**: `MSA/`

- **`Install-sMSA_ADAccount.ps1`** - Standalone MSA management
  - Creates and installs standalone Managed Service Accounts
  - Supports Active Directory and Exchange On-Demand Assessment configurations
  - Comprehensive error handling with specific exit codes

- **`Install-gMSA_ADAccount.ps1`** - Group MSA management
  - Creates and manages Group Managed Service Accounts
  - Multi-server support through security group membership
  - KDS Root Key creation and validation

- **`Update-ScheduledTaskToMSA.ps1`** - Task migration to MSA
  - Migrates existing scheduled tasks to use MSA authentication
  - Validates MSA installation and task existence
  - Preserves task settings while updating credentials

- **`Update-TaskSchedule.ps1`** - OMS task scheduling
  - Updates Microsoft Operations Management Suite task triggers
  - Interactive grid-view selection for bulk updates
  - WhatIf mode for safe testing

### ?? Media Processing

**Location**: `HEVC Conversion/`

- **`StreamShift_1.0.9.ps1`** - Video transcoding and optimization
  - Automated HEVC/x265 video conversion
  - Recursive directory scanning and codec detection
  - Container optimization (MP4 to MKV)
  - 20-50% file size reduction with quality preservation

## ?? Quick Start

### Prerequisites

- Windows PowerShell 5.1+ or PowerShell 7+
- Administrative privileges for most scripts
- Appropriate Azure/Active Directory permissions where applicable

### Basic Usage

```powershell
# Clone the repository
git clone <repository-url>
cd Public

# Navigate to desired script category
cd MSA
.\Install-sMSA_ADAccount.ps1 -MSAName "MyServiceAccount"

cd ..\DNS
.\GET-DNSScavengingData.ps1 -Verbose

cd "..\Azure-Extensions"
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "Production-Servers"
```

## ?? Features

### Common Features Across Scripts

- ? Comprehensive error handling and logging
- ? Verbose output support for troubleshooting
- ? Parameter validation and input verification
- ? Progress tracking and status reporting
- ? CSV export capabilities for reporting
- ? WhatIf support where applicable
- ? Pipeline input support

### Security Features

- ?? MSA-based authentication (where applicable)
- ?? Principle of least privilege
- ?? Comprehensive audit trails
- ?? Safe operation modes with validation
- ?? No hardcoded credentials

### Enterprise Features

- ?? Bulk operations support
- ?? Network storage compatibility
- ?? Multi-domain/subscription support
- ?? Comprehensive reporting and analytics
- ?? Integration with existing infrastructure

## ?? Documentation

Each script includes comprehensive PowerShell help documentation:

```powershell
Get-Help .\ScriptName.ps1 -Full
Get-Help .\ScriptName.ps1 -Examples
Get-Help .\ScriptName.ps1 -Parameter ParameterName
```

## ?? Script Categories

| Category | Purpose | Key Benefits |
|----------|---------|--------------|
| **Azure Extensions** | Azure Arc server management | Automated extension updates, compliance reporting |
| **DNS Management** | DNS infrastructure auditing | Scavenging configuration analysis, multi-DC reporting |
| **MSA Management** | Service account automation | Enhanced security, automated password management |
| **Media Processing** | Video optimization | Storage savings, format standardization |

## ?? Requirements by Category

### Azure Scripts

- Azure CLI or Azure PowerShell modules
- Azure subscription with appropriate permissions
- Network connectivity to Azure resources

### Active Directory Scripts

- Active Directory PowerShell module
- Domain administrator privileges (for MSA operations)
- Network connectivity to domain controllers

### Media Processing Scripts

- FFmpeg and FFprobe executables
- Sufficient storage for processing
- Modern CPU for optimal performance

## ??? Installation & Setup

### 1. PowerShell Modules

```powershell
# Install required modules (run as administrator)
Install-Module Az.ConnectedMachine    # For Azure Arc scripts
Install-Module ActiveDirectory        # For MSA and DNS scripts
Install-Module PSLogging             # For enhanced logging
```

### 2. External Tools

- **Azure CLI**: Download from [Microsoft Azure CLI](https://docs.microsoft.com/en-us/cli/azure/)
- **FFmpeg**: Download from [FFmpeg.org](https://ffmpeg.org/) or [FFBinaries](https://ffbinaries.com/)

### 3. Permissions Setup

- Ensure appropriate Active Directory permissions for MSA operations
- Configure Azure authentication (az login or Connect-AzAccount)
- Verify local administrator rights where required

## ?? Usage Examples

### Azure Arc Extension Management

```powershell
# Generate extension report
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "Production"

# Update all outdated extensions
.\Manage-AzureArcExtensions.ps1 -ResourceGroup "Production" -Update
```

### DNS Scavenging Analysis

```powershell
# Collect scavenging data with detailed logging
.\GET-DNSScavengingData.ps1 -Verbose

# Generate scavenging report
.\"PowerShell Script for DNS Scavenging Report.ps1"
```

### MSA Deployment

```powershell
# Create standalone MSA for AD assessment
.\Install-sMSA_ADAccount.ps1 -MSAName "MSA_ADAssess" -AD_ODA

# Create group MSA for multi-server deployment
.\Install-gMSA_ADAccount.ps1 -gMSAName "WebApp_gMSA" -gMSAGroupServers @('Web01$','Web02$')
```

### Video Processing

```powershell
# Analyze video collection
.\StreamShift_1.0.9.ps1 -InputPath "D:\Videos" -LogOnly

# Convert videos to HEVC
.\StreamShift_1.0.9.ps1 -InputPath "D:\Videos"
```

## ?? Contributing

We welcome contributions to improve these scripts! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Test** your changes thoroughly
4. **Update** documentation as needed
5. **Commit** your changes (`git commit -m 'Add amazing feature'`)
6. **Push** to the branch (`git push origin feature/amazing-feature`)
7. **Open** a Pull Request

### Contribution Standards

- Follow PowerShell best practices and coding standards
- Include comprehensive help documentation
- Add appropriate error handling and logging
- Test in multiple environments where possible
- Update README.md if adding new scripts

## ?? License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ?? Disclaimer

This code is provided for demonstration purposes only. It is intended to illustrate concepts and should not be used in production environments without proper review, testing, and validation. The authors and distributors of this code make no warranties regarding its functionality, security, or suitability for any specific use. Use at your own risk.

Always test scripts in a safe environment before deploying to production systems.

## ?? Contact

For questions, feedback, or support:

- **Email**: <GitHub@ffournier.ca>
- **GitHub**: [@Frafou](https://github.com/Frafou)

## ??? Tags

`PowerShell` `Azure` `Active Directory` `DNS` `MSA` `HEVC` `Automation` `Enterprise` `Windows Administration` `Video Processing` `System Administration`
