$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = 'C:\Users\MSI\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$Node = 'C:\Users\MSI\AppData\Local\OpenAI\Codex\bin\node.exe'

function Test-PortFree {
  param([int]$Port)
  $listener = $null
  try {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), $Port)
    $listener.Start()
    return $true
  } catch {
    return $false
  } finally {
    if ($listener) { $listener.Stop() }
  }
}

function Test-CommandWorks {
  param([string]$Command, [string[]]$Args)
  try {
    $p = Start-Process -FilePath $Command -ArgumentList $Args -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$env:TEMP\ijroda_cmd_out.txt" -RedirectStandardError "$env:TEMP\ijroda_cmd_err.txt"
    return $p.ExitCode -eq 0
  } catch {
    return $false
  }
}

if (-not (Test-Path -LiteralPath $Python)) {
  $Python = 'python'
}
if (-not (Test-Path -LiteralPath $Node)) {
  $Node = 'node'
}

$Port = 5177
while (-not (Test-PortFree -Port $Port)) {
  $Port++
}

$Url = "http://127.0.0.1:$Port/"
Write-Host "Ijroda lokal server ishga tushyapti..." -ForegroundColor Cyan
Write-Host "Manzil: $Url" -ForegroundColor Green
Write-Host "Bu oynani yopmang. Yopsangiz server ham to'xtaydi." -ForegroundColor Yellow

Start-Process $Url
Set-Location -LiteralPath $Root

if (Test-CommandWorks -Command $Python -Args @('--version')) {
  & $Python -m http.server $Port --bind 127.0.0.1
} elseif (Test-CommandWorks -Command $Node -Args @('--version')) {
  & $Node "$Root\tools\static-server.mjs" $Root $Port 127.0.0.1
} else {
  Write-Host "Python ham, Node ham topilmadi. Dastur serveri ishga tushmadi." -ForegroundColor Red
  Write-Host "Node.js o'rnating yoki GitHub Pages manzilidan foydalaning." -ForegroundColor Yellow
  exit 1
}
