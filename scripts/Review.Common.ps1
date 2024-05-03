function Invoke-ReviewCore {
    param(
        [string] $Python,
        [string[]] $Options,
        [string[]] $InputPaths,
        [ref] $Status
    )

    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $false
    $PSNativeCommandArgumentPassing = 'Standard'
    try {
        $application = Get-Command -Name $Python -CommandType Application | Select-Object -First 1
        $arguments = @('-m', 'fortigate_review') + $Options + '--'
        foreach ($path in $InputPaths) {
            $provider = $null
            $drive = $null
            $arguments += $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                $path, [ref] $provider, [ref] $drive
            )
            if ($provider.Name -ne 'FileSystem') {
                throw 'Input paths must use the filesystem provider.'
            }
        }
        Push-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
        try {
            & $application.Source @arguments
            $Status.Value = $LASTEXITCODE
        } finally {
            Pop-Location
        }
    } catch {
        [Console]::Error.WriteLine('error: could not invoke the review CLI: ' + $_.Exception.Message)
        $Status.Value = 2
    }
}
