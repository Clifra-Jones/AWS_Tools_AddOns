#
# Module manifest for module 'AWS_Tools_AddOns'
#
# Generated by: Cliff Williams
#
# Generated on: 10/29/2024
#

@{

# Script module or binary module file associated with this manifest.
RootModule = './AWS_Tools_AddOns.psm1'

# Version number of this module.
ModuleVersion = '0.0.9'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '4c25b38e-62db-4312-bede-7712e3551424'

# Author of this module
Author = 'Cliff Williams'

# Company or vendor of this module
CompanyName = 'Balfour Beatty US'

# Copyright statement for this module
Copyright = '(c) Balfour Beatty US. All rights reserved.'

# Description of the functionality provided by this module
Description = 'A set of helper function that enhances using AWS.Tools.Powershell'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '7.0'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @('AWS.Tools.S3', 
               'AWS.Tools.EC2', 
               'Microsoft.PowerShell.SecretManagement', 
               'Microsoft.PowerShell.SecretStore', 
               'AWS.Tools.SecurityToken')

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
ScriptsToProcess = 'Private.ps1'

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-S3Folder', 'Restore-S3Folder', 'Get-S3RestoreProgress', 
               'Get-EC2InstanceList', 'Get-DiskMappings', 'Get-IAMUserPermissions', 
               'Get-IAMGroupPermissions', 'Get-IAMRolePermissions', 
               'Set-SecretVault', 'Set-SecureAWSCredentials'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'AWS','AWS.Tools.Powershell'

        # A URL to the license for this module.
        LicenseUri = 'https://opensource.org/license/ms-pl-html/'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Clifra-Jones/AWS_Tools_AddOns'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = 'Helper module for working with AWS Tools for Powershell.'

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

