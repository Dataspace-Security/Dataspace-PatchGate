# Parse-check PowerShell scripts with the real PowerShell parser (no execution).
#   pwsh -NoProfile -File release/lib/check-powershell.ps1 <file.ps1> [...]
# Works on Windows PowerShell 5.1 (the endpoint runtime) and PowerShell 7 (CI / container).
# Exit code = number of files with parse errors.
param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Paths)
$ErrorActionPreference = 'Stop'
$failed = 0
foreach ($p in $Paths) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $p).Path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $failed++
        foreach ($e in $errors) {
            Write-Output ("    FAIL  {0}:{1}:{2} {3}" -f $p, $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
        }
    } else {
        Write-Output ("    ok    {0}" -f $p)
    }
}
exit $failed
