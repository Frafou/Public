<#
.SYNOPSIS
    Browse-Files PowerShell Module - File and Folder Selection Dialogs

.DESCRIPTION
    This PowerShell module provides enterprise-grade file and folder selection dialog functionality
    for interactive PowerShell scripts and applications. It offers user-friendly graphical interfaces
    for file system navigation, supporting various file filters, directory selection, and error handling.

    The module encapsulates Windows Forms dialog functionality to provide consistent, reliable
    file and folder selection capabilities across PowerShell scripts, making it ideal for
    automation scenarios requiring user interaction and file system operations.

    Key Features:
    - Interactive folder selection with configurable root directories
    - File selection dialogs with customizable filters and file type restrictions
    - Enterprise-grade error handling and user feedback
    - Cross-platform Windows Forms integration
    - Consistent user experience across PowerShell applications
    - Exported error logging preferences for centralized error management

.NOTES
    File Name      : Browse-Files.psm1
    Author         : Francois Fournier
    Version        : 1.1
    Last Modified  : December 6, 2024
    Purpose        : File and Folder Selection Dialog Module

    Module Functions:
    - Select-FolderDialog: Interactive folder selection with root directory options
    - Select-FileDialog: File selection with customizable filters and file type support

    Prerequisites:
    - Windows PowerShell 5.0+ or PowerShell 7+
    - System.Windows.Forms assembly (included with Windows)
    - Windows operating system with GUI support
    - Interactive session (not suitable for headless/service scenarios)

    Security Considerations:
    - Module provides read-only file system access through dialogs
    - User interaction required - not suitable for automated/unattended scenarios
    - Error logging may contain sensitive path information - secure log files appropriately
    - Validate selected paths before use in security-sensitive operations

    Performance Considerations:
    - Dialog operations are synchronous and block script execution
    - Large directory structures may impact dialog responsiveness
    - Assembly loading occurs on first function call

    Related Documentation:
    - System.Windows.Forms.FolderBrowserDialog: https://docs.microsoft.com/dotnet/api/system.windows.forms.folderbrowserdialog
    - System.Windows.Forms.OpenFileDialog: https://docs.microsoft.com/dotnet/api/system.windows.forms.openfiledialog
    - PowerShell Modules: https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_modules

.COMPONENT
    System.Windows.Forms

.ROLE
    User Interface, File System Navigation

.FUNCTIONALITY
    File Selection, Directory Browsing, User Interface
#>

#Requires -Version 5.0

# Load required assembly once at module level
Add-Type -AssemblyName System.Windows.Forms


function Select-FolderDialog {
    <#
    .SYNOPSIS
        Displays an interactive folder selection dialog for directory browsing and selection.

    .DESCRIPTION
        This function provides a user-friendly graphical interface for folder selection using
        Windows Forms FolderBrowserDialog. It allows users to navigate the directory structure
        and select a target folder for script operations, file processing, or configuration.

        The function supports configurable root directories, custom descriptions, and comprehensive
        error handling for scenarios where users cancel the operation or encounter access issues.
        Essential for interactive PowerShell scripts requiring user-specified directory paths.

    .PARAMETER Description
        Specifies the description text displayed in the folder selection dialog window.
        This text helps users understand the purpose of the folder selection and provides
        context for the operation being performed.
        Default: "Select Folder"

    .PARAMETER RootFolder
        Specifies the initial root folder for the dialog navigation tree. This parameter
        accepts Environment.SpecialFolder enumeration values to provide consistent starting
        points across different systems and user profiles.

        Common values: Desktop, MyDocuments, MyComputer, ProgramFiles, System
        Default: "Desktop"

        Reference: https://docs.microsoft.com/dotnet/api/system.environment.specialfolder

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.String
            Returns the full path of the selected folder if user confirms selection.

        Error
            Generates terminating error if user cancels the operation.

    .EXAMPLE
        $targetFolder = Select-FolderDialog -Description "Select backup destination" -RootFolder "MyDocuments"

        Displays a folder selection dialog starting from the user's Documents folder with
        a custom description for backup destination selection.

    .EXAMPLE
        $logPath = Select-FolderDialog -Description "Choose log file directory" -RootFolder "MyComputer"

        Opens folder dialog starting from Computer view for system-wide directory selection,
        useful for administrative scripts requiring specific log locations.

    .EXAMPLE
        try {
            $sourceDir = Select-FolderDialog -Description "Select source directory for processing"
            Write-Host "Selected directory: $sourceDir"
        } catch {
            Write-Warning "Folder selection cancelled by user"
        }

        Demonstrates proper error handling for user cancellation scenarios.

    .NOTES
        Function Name  : Select-FolderDialog
        Author         : Francois Fournier
        Last Modified  : December 6, 2024
        Version        : 1.1

        Prerequisites:
        - Windows PowerShell 5.0+ or PowerShell 7+
        - System.Windows.Forms assembly
        - Interactive Windows session with GUI support

        Behavior:
        - Function blocks execution until user makes selection or cancels
        - Generates terminating error on user cancellation
        - Returns absolute path string on successful selection
        - Uses module-level loaded Windows Forms assembly

        Security Considerations:
        - Function provides read-only directory browsing
        - Returned paths should be validated before use
        - Consider access permissions for selected directories

        Related Functions:
        - Select-FileDialog: For individual file selection
        - Get-Location: For current working directory
        - Test-Path: For validating selected paths

    .LINK
        https://docs.microsoft.com/dotnet/api/system.windows.forms.folderbrowserdialog

    .LINK
        https://docs.microsoft.com/dotnet/api/system.environment.specialfolder
    #>
    param(
        [string]$Description = 'Select Folder',
        [ValidateSet('Desktop', 'MyDocuments', 'MyComputer', 'ProgramFiles', 'System', 'ApplicationData', 'CommonApplicationData', 'MyMusic', 'MyPictures', 'MyVideos', 'Recent', 'SendTo', 'StartMenu', 'Startup', 'Templates')]
        [string]$RootFolder = 'Desktop'
    )

    try {
        $objForm = New-Object System.Windows.Forms.FolderBrowserDialog
        $objForm.RootFolder = [System.Environment+SpecialFolder]::$RootFolder
        $objForm.Description = $Description
        $objForm.ShowNewFolderButton = $true

        $Show = $objForm.ShowDialog()
        if ($Show -eq [System.Windows.Forms.DialogResult]::OK) {
            return $objForm.SelectedPath
        } else {
            Write-Error "Folder selection operation cancelled by user." -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Failed to display folder selection dialog: $($_.Exception.Message)" -ErrorAction Stop
    }
    finally {
        if ($objForm) {
            $objForm.Dispose()
        }
    }
}
#end function Select-FolderDialog

function Select-FileDialog {
    <#
    .SYNOPSIS
        Displays an interactive file selection dialog for individual file browsing and selection.

    .DESCRIPTION
        This function provides a comprehensive graphical interface for file selection using
        Windows Forms OpenFileDialog. It enables users to navigate the file system, apply
        file type filters, and select specific files for script processing or configuration.

        The function supports extensive file filtering capabilities, custom dialog titles,
        initial directory specification, and robust error handling for user cancellation
        scenarios. Essential for interactive PowerShell scripts requiring user-specified
        file paths with type validation and selection constraints.

    .PARAMETER Title
        Specifies the title text displayed in the file selection dialog window.
        This title helps users understand the purpose of the file selection and provides
        context for the operation being performed on the selected file.

    .PARAMETER Directory
        Specifies the initial directory path for the file dialog. The dialog will open
        at this location, allowing users to start browsing from a specific directory
        rather than the system default location.

    .PARAMETER Filter
        Specifies the file type filter for the dialog, controlling which files are visible
        and selectable. Uses standard Windows file dialog filter syntax with display names
        and file extensions.

        Format: "Description|Pattern|Description|Pattern"
        Examples:
        - "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        - "PowerShell files (*.ps1)|*.ps1|PowerShell modules (*.psm1)|*.psm1"
        - "Log files (*.log)|*.log|CSV files (*.csv)|*.csv"

        Default: "All Files (*.*)|*.*"

        Reference: https://docs.microsoft.com/dotnet/api/system.windows.forms.filedialog.filter

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.String
            Returns the full path of the selected file if user confirms selection.

        Error
            Generates terminating error if user cancels the operation.

    .EXAMPLE
        $configFile = Select-FileDialog -Title "Select configuration file" -Directory "C:\\Config" -Filter "XML files (*.xml)|*.xml|JSON files (*.json)|*.json"

        Opens file dialog in C:\Config directory with XML and JSON file filters,
        allowing user to select configuration files for application setup.

    .EXAMPLE
        $logFile = Select-FileDialog -Title "Choose log file for analysis" -Directory $PWD -Filter "Log files (*.log)|*.log|Text files (*.txt)|*.txt"

        Displays file selection dialog in current directory with log and text file filters,
        useful for log analysis scripts requiring specific file input.

    .EXAMPLE
        try {
            $csvFile = Select-FileDialog -Title "Select data file" -Filter "CSV files (*.csv)|*.csv|Excel files (*.xlsx)|*.xlsx"
            Import-Csv $csvFile | Select-Object -First 5
        } catch {
            Write-Warning "File selection cancelled by user"
        }

        Demonstrates file selection with error handling and immediate file processing.

    .EXAMPLE
        $scriptFile = Select-FileDialog -Title "Select PowerShell script" -Directory "$env:USERPROFILE\\Documents\\WindowsPowerShell" -Filter "PowerShell files (*.ps1)|*.ps1"

        Opens dialog in user's PowerShell directory with PowerShell script filter,
        ideal for script management and execution scenarios.

    .NOTES
        Function Name  : Select-FileDialog
        Author         : Francois Fournier
        Last Modified  : December 6, 2024
        Version        : 1.1

        Prerequisites:
        - Windows PowerShell 5.0+ or PowerShell 7+
        - System.Windows.Forms assembly
        - Interactive Windows session with GUI support

        Behavior:
        - Function blocks execution until user makes selection or cancels
        - Generates terminating error on user cancellation
        - Returns absolute file path string on successful selection
        - Uses module-level loaded Windows Forms assembly
        - Validates directory accessibility before opening dialog

        Security Considerations:
        - Function provides file path selection only, not file content access
        - Returned file paths should be validated before use
        - Consider file permissions and access rights for selected files
        - Validate file types and sizes before processing

        Filter Syntax:
        - Use pipe (|) to separate display text from pattern
        - Multiple filters separated by pipe characters
        - Wildcard patterns: * (multiple characters), ? (single character)
        - Case-insensitive pattern matching

        Related Functions:
        - Select-FolderDialog: For directory selection
        - Test-Path: For validating selected file paths
        - Get-Item: For retrieving file information
        - Import-Csv, Get-Content: For file processing

    .LINK
        https://docs.microsoft.com/dotnet/api/system.windows.forms.openfiledialog

    .LINK
        https://docs.microsoft.com/dotnet/api/system.windows.forms.filedialog.filter
    #>
    param(
        [string]$Title = 'Select File',
        [string]$Directory = $PWD,
        [string]$Filter = 'All Files (*.*)|*.*'
    )

    # Validate directory exists if specified
    if ($Directory -and -not (Test-Path -Path $Directory -PathType Container)) {
        Write-Warning "Specified directory '$Directory' does not exist. Using current directory instead."
        $Directory = $PWD
    }

    try {
        $objForm = New-Object System.Windows.Forms.OpenFileDialog
        $objForm.InitialDirectory = $Directory
        $objForm.Filter = $Filter
        $objForm.Title = $Title
        $objForm.CheckFileExists = $true
        $objForm.CheckPathExists = $true

        $Show = $objForm.ShowDialog()
        if ($Show -eq [System.Windows.Forms.DialogResult]::OK) {
            return $objForm.FileName
        } else {
            Write-Error "File selection operation cancelled by user." -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Failed to display file selection dialog: $($_.Exception.Message)" -ErrorAction Stop
    }
    finally {
        if ($objForm) {
            $objForm.Dispose()
        }
    }
}
#end function Select-FileDialog

Export-ModuleMember -Function Select-FileDialog, Select-FolderDialog
