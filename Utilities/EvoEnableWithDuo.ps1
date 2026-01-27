<#
.SYNOPSIS
Enables Evo Agent with Duo
Copyright 2026 by Evo Security Technologies, Inc.

.DESCRIPTION
Enables the Evo Agent to work alongside Duo when Duo is the sole credential provider. Also has a flag to remove Evo from the Duo whitelist.

.PARAMETER Add
Adds the Evo Agent to the Duo WhiteList

.PARAMETER Remove
Removes the Evo Agent from Duo WhiteList

.PARAMETER List
Lists the credential providers in the Duo whitelist without modifying it

.PARAMETER Help
    Displays usage information

#>

[CmdletBinding(DefaultParameterSetName='HelpConfig')]
param(
    [Parameter(ParameterSetName='AddConfig')]
    [switch] $Add,

    [Parameter(ParameterSetName='RemoveConfig')]
    [switch] $Remove,
    
    [Parameter(ParameterSetName='ListOnlyConfig')]
    [switch] $List,

    [Parameter(ParameterSetName='HelpConfig')]
    [switch] $Help
)

function Show-Help {
    Write-Host "EvoEnableWithDuo.ps1 - Configure Evo Agent with Duo" -ForegroundColor Cyan
    Write-Host "" 
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\\EvoEnableWithDuo.ps1 -Add" 
    Write-Host "  .\\EvoEnableWithDuo.ps1 -Remove" 
    Write-Host "  .\\EvoEnableWithDuo.ps1 -List" 
    Write-Host "  .\\EvoEnableWithDuo.ps1 -Help" 
    Write-Host "" 
    Write-Host "Parameters:" -ForegroundColor Yellow
    Write-Host "  -Add    Adds the Evo Agent to the Duo whitelist." 
    Write-Host "  -Remove Removes the Evo Agent from the Duo whitelist." 
    Write-Host "  -List   Lists the credential providers in the Duo whitelist without modifying it." 
    Write-Host "  -Help   Displays this usage information." 
}

if (-not $Add -and -not $Remove -and -not $List -and -not $Help) {
    $Help = $true
}

if ($Help) {
    Show-Help
    return
}

function IsRunningAsAdministrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


if (-not (IsRunningAsAdministrator) -and (-not $List)){
    throw "Need to run this script as an Administrator"
}

$DuoKeyName = 'Software\Duo Security\DuoCredProv'
$WhiteListName = 'ProvidersWhitelist'

$writeEnabled = -not $List
try {
    $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($DuoKeyName, $writeEnabled)

    if (-not $Key) {
        throw "Duo not detected/installed"
    }

    $EvoCredProviderClsid = '{a81f782d-cf30-439a-bad8-645d9862ea99}'
    $Whitelist = $Key.GetValue($WhiteListName)

    function Notify($obj)
    {
        Write-Host -fore Green -back Black $obj
    }

    function AddEvo
    {
        if (-not $Whitelist ) {
            $Key.SetValue($WhiteListName, [string[]] @($EvoCredProviderClsid))
        } else {
            if (-not ($Whitelist -contains $EvoCredProviderClsid)){
                $NewProviders = [string[]] ($Whitelist + $EvoCredProviderClsid)
                $Key.SetValue($WhiteListName, $NewProviders)
            } else {
                Notify 'Already contains Evo Agent'
            }
        }
    }

    function RemoveEvo
    {
        if (-not $Whitelist) {
            Notify 'No existing Duo WhiteList'
        } else {
            $idx = $Whitelist.IndexOf($EvoCredProviderClsid)
            if ($idx -ne -1) {
                $List = [System.Collections.ArrayList]::new($Whitelist)
                $List.RemoveAt($idx)
            
                $RemovedProviders = [string[]] ($List.ToArray())
                $Key.SetValue($WhiteListName, $RemovedProviders)
            } else {
                Notify 'Evo not found in Duo WhiteList'
            }
        }
    }

    if ($Add) {
        AddEvo
    } elseif ($Remove) {
        RemoveEvo
    }

    $Value = $Key.GetValue($WhiteListName)
    "Duo WhiteList: $Value"
}
finally {
    if ($Key) { 
		$Key.Close()
	}
}
