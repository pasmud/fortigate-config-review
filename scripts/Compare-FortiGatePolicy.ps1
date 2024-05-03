#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Before,

    [Parameter(Mandatory, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string] $After,

    [ValidateSet('Text', 'Json')]
    [string] $Format = 'Text',

    [switch] $FailOnChange,

    [ValidateNotNullOrEmpty()]
    [string] $Python = 'python'
)

. "$PSScriptRoot/Review.Common.ps1"
$options = @('diff', '--format', $Format.ToLowerInvariant())
if ($FailOnChange) {
    $options += '--fail-on-change'
}
$status = 2
Invoke-ReviewCore -Python $Python -Options $options -InputPaths @($Before, $After) `
    -Status ([ref] $status)
exit $status
