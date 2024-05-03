#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Path,

    [ValidateSet('Text', 'Json')]
    [string] $Format = 'Text',

    [ValidateNotNullOrEmpty()]
    [string] $Python = 'python'
)

. "$PSScriptRoot/Review.Common.ps1"
$status = 2
Invoke-ReviewCore -Python $Python -Options @('summary', '--format', $Format.ToLowerInvariant()) `
    -InputPaths @($Path) -Status ([ref] $status)
exit $status
