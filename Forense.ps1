
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "run this script as Admin."
    Start-Sleep 10
    Exit
}


Clear-Host

Write-Host @"


 
__________           .___ .__          __                 ___________                                .__        
\______   \ ____   __| _/ |  |   _____/  |_ __ __  ______ \_   _____/__________   ____   ____   _____|__| ____  
 |       _// __ \ / __ |  |  |  /  _ \   __\  |  \/  ___/  |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\ 
 |    |   \  ___// /_/ |  |  |_(  <_> )  | |  |  /\___ \   |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ 
 |____|_  /\___  >____ |  |____/\____/|__| |____//____  >  \___  / \____/|__|    \___  >___|  /____  >__|\___  >
        \/     \/     \/                              \/       \/                    \/     \/     \/        \/ 


"@ -ForegroundColor Red

Write-Host "By Kenzooq For Red Lotus " -ForegroundColor Blue
Write-Host 



Write-Host "Bienvenido"
Write-Host "1. Scan Forensics Tools" -ForegroundColor Cyan
Write-Host "Select option "
$opcion = Read-Host


switch ($opcion) {
    1 {
       
        Write-Host "Scaning...."
        
Write-Host "Dependencies" -ForegroundColor DarkBlue
Write-Host
Write-Host "Bstrings https://f001.backblazeb2.com/file/EricZimmermanTools/net6/bstrings.zip" -ForegroundColor DarkCyan
Write-Host "TimelineExplorer https://f001.backblazeb2.com/file/EricZimmermanTools/net6/TimelineExplorer.zip" -ForegroundColor DarkCyan
Write-Host "SrumECmd https://f001.backblazeb2.com/file/EricZimmermanTools/net6/SrumECmd.zip" -ForegroundColor DarkCyan
Write-Host "Rla https://f001.backblazeb2.com/file/EricZimmermanTools/net6/rla.zip" -ForegroundColor DarkCyan
Write-Host "MFTECmd https://f001.backblazeb2.com/file/EricZimmermanTools/net6/MFTECmd.zip" -ForegroundColor DarkCyan
Write-Host
Write-Host "Bstrings" -ForegroundColor Cyan

function LoadingAnimation {
    $barLength = 20
    for ($i = 0; $i -le $barLength; $i++) {
        $bar = '[' + '=' * $i + ' ' * ($barLength - $i) + ']'
        Write-Host -NoNewline "`r$bar"
        Start-Sleep -Milliseconds 100
    }
    Write-Host ""
}

LoadingAnimation


$outputFile = "Bstrings_Results.csv"


Invoke-Expression "cmd /c bstrings.exe -f C:\Windows\system32\config\SYSTEM --ls harddiskvolume" | Out-Null

$output | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host 
Write-host "Analyzing Bstrings" -ForegroundColor Blue
Write-Host "Bstrings saved in .csv" -ForegroundColor Green
Write-Host
Write-Host "SrumECmd" -ForegroundColor DarkGreen

function LoadingAnimation {
    $barLength = 15
    for ($i = 0; $i -le $barLength; $i++) {
        $bar = '[' + '=' * $i + ' ' * ($barLength - $i) + ']'
        Write-Host -NoNewline "`r$bar"
        Start-Sleep -Milliseconds 100
    }
    Write-Host ""
    Write-Host "¡Carga completa!"
}

LoadingAnimation

Invoke-Expression "cmd /c SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv ." | Out-Null
Write-Host 
Write-host "Analyzing SrumECmd" -ForegroundColor Blue
Write-Host "SrumECmd saved in .csv" -ForegroundColor Green
Write-Host
Write-Host "Rla......" -ForegroundColor DarkCyan

function LoadingAnimation {
    $barLength = 15
    for ($i = 0; $i -le $barLength; $i++) {
        $bar = '[' + '=' * $i + ' ' * ($barLength - $i) + ']'
        Write-Host -NoNewline "`r$bar"
        Start-Sleep -Milliseconds 100
    }
    Write-Host ""
}

LoadingAnimation

Invoke-Expression "cmd /c rla.exe -f C:\Windows\System32\config\SYSTEM --out ." | Out-Null
Write-Host 
Write-host "Analyzing Rla" -ForegroundColor Blue
Write-Host
Write-Host "MFTECmd" -ForegroundColor Yellow

function LoadingAnimation {
    $barLength = 35
    for ($i = 0; $i -le $barLength; $i++) {
        $bar = '[' + '=' * $i + ' ' * ($barLength - $i) + ']'
        Write-Host -NoNewline "`r$bar"
        Start-Sleep -Milliseconds 100
    }
    Write-Host ""
}

LoadingAnimation

Invoke-Expression "cmd /c MFTECmd.exe -f c:\MFT --csv ." | Out-Null
Write-host "Analyzing MFTECmd" -ForegroundColor Blue
Write-Host "MFTECmd saved in .csv" -ForegroundColor Green
Write-Host
    }
    2 {
        Write-Host
        Write-Host "Information"
        Write-Host " Trackings" -ForegroundColor Green

function LoadingAnimation {
    $barLength = 35
    for ($i = 0; $i -le $barLength; $i++) {
        $bar = '[' + '=' * $i + ' ' * ($barLength - $i) + ']'
        Write-Host -NoNewline "`r$bar"
        Start-Sleep -Milliseconds 100
    }
    Write-Host ""
    Write-Host "¡Carga completa!"
}
