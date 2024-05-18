#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Path,

    [ValidateSet('Text', 'Json')]
    [string] $Format = 'Text',

    [ValidateNotNullOrEmpty()]
    [string] $Python = 'python',

    [ValidateSet('Enable', 'Disable')]
    [string] $PolicyStatus
)

. "$PSScriptRoot/Review.Common.ps1"
$options = @('summary', '--format', $Format.ToLowerInvariant())
if ($PSBoundParameters.ContainsKey('PolicyStatus')) {
    $options += @('--policy-status', $PolicyStatus.ToLowerInvariant())
}
$status = 2
Invoke-ReviewCore -Python $Python -Options $options -InputPaths @($Path) -Status ([ref] $status)
exit $status
