$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = 'C:\Users\MSI\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
  $Python = 'python'
}

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
& $Python -m http.server $Port --bind 127.0.0.1
