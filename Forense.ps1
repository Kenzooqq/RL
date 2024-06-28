
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Por favor, ejecuta este script como administrador."
    Start-Sleep 10
    Exit
}

Write-Host "El script se está ejecutando desde la ubicación correcta."

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
Write-Host "1. Scanear" -ForegroundColor Cyan
Write-Host "2. Recopilar información" -ForegroundColor Cyan
Write-Host "Por favor, elige una opción (1 o 2): "
$opcion = Read-Host


switch ($opcion) {
    1 {
       
        Write-Host "Escaneando...."
        
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
    Write-Host "¡Carga completa!"
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
    Write-Host "¡Carga completa!"
}

LoadingAnimation
    }
    2 {
        Write-Host
        Write-Host "Recopilar Informacion"
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

LoadingAnimation

Invoke-Expression "cmd /c MFTECmd.exe -f c:\MFT --csv ." | Out-Null
Write-host "Analyzing MFTECmd" -ForegroundColor Blue
Write-Host "MFTECmd saved in .csv" -ForegroundColor Green
Write-Host 
Write-Host "--------------------------------------------------"
Write-Host "Dps" -ForegroundColor Red
Write-Host "--------------------------------------------------"

Write-Host "^!![A-Z]((?!Exe).)*$ / " -ForegroundColor White

Write-Host " !! => .exe" -ForegroundColor White

Write-Host "\device\harddiskvolumev => .exe" -ForegroundColor White

Write-Host "--------------------------------------------------"
Write-Host "DiagTrack" -ForegroundColor DarkMagenta
Write-Host "--------------------------------------------------"

Write-Host "^\\device\\harddiskvolume((?!Exe|dll).)*$ " -ForegroundColor White

Write-Host "device\harddiskvolume -> .exe" -ForegroundColor White

Write-Host "--------------------------------------------------"
Write-Host "Csrss" -ForegroundColor DarkCyan
Write-Host "--------------------------------------------------"

Write-Host "^(?!C:)[A-Z]:[\\](?!\+|(u){FFFF}|rkr)" -ForegroundColor White

Write-Host ":\ => .exe" -ForegroundColor White

Write-Host "^[a-z]:.+\.((?!exe|pyd|manifest|dll|config|\\|cpl|microsoft-|shell).)*$" -ForegroundColor White

Write-Host "--------------------------------------------------"
Write-Host "Appinfo" -ForegroundColor Yellow
Write-Host "--------------------------------------------------"

Write-Host ":\ -> .exe" -ForegroundColor White

Write-Host "C:\ > .exe" -ForegroundColor White

Write-Host "--------------------------------------------------"
Write-Host "SysMain" -ForegroundColor  Cyan
Write-Host "--------------------------------------------------"

Write-Host "harddiskvolume > .exe"

Write-Host ".exe.config"

Write-Host ":\ > .exe"

Write-Host "--------------------------------------------------"
Write-Host "Sgmrbroker" -ForegroundColor DarkBlue
Write-Host "--------------------------------------------------"

Write-Host "device > harddiskvolume > .exe"
Write-Host "exitcode"

Write-Host "--------------------------------------------------"
Write-Host "cftmon" -ForegroundColor DarkGreen
Write-Host "--------------------------------------------------"

Write-Host "^[A-Z]:.+.\\((?!exe).)*$ - Exclude exes"
Write-Host "^[A-Z]:.+.\\((?!dll).)*$ - Exclude dlls"
Write-Host
Write-Host "Searching bypass..." -ForegroundColor Yellow
Write-Host
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

LoadingAnimation

$stopwatch = [Diagnostics.Stopwatch]::StartNew()

$historySaveStyle = (Get-PSReadlineOption).HistorySaveStyle

if ($historySaveStyle -eq "SaveNothing") {
    Write-Host "El historial de PowerShell está desactivado."
} else {
    Write-Host "El historial de PowerShell está activado."
}

Write-Host "--------------------------------------------------"
Write-Host
$regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System"
$regValueName = "DisableCMD"

if (Test-Path $regPath) {
    $value = (Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue).$regValueName

    if ($value -eq 1) {
        Write-Host "El acceso al CMD está deshabilitado."
    } else {
        Write-Host "El acceso al CMD está habilitado."
    }
} else {
    Write-Host "No se ha realizado ninguna configuración para deshabilitar el acceso a CMD."
}

Write-Host "--------------------------------------------------"

$keyPath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "DisableTaskMgr"

$value = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue

if ($value) {
    Write-Output "El Administrador de tareas está deshabilitado."
} else {
    Write-Output "El Administrador de tareas está habilitado."
}

Write-Host "--------------------------------------------------"
Write-Host
Write-Host "Searching Services..." -ForegroundColor Magenta
Write-Host
LoadingAnimation

function VerificarEstadoServicio {
    param (
        [string]$ServicioNombre
    )

    $servicio = Get-Service -Name $ServicioNombre -ErrorAction SilentlyContinue 

    if ($servicio) {
        Write-Host "El servicio $ServicioNombre está presente en el sistema." 

        if ($servicio.Status -eq 'Running') {
            Write-Host "Estado del servicio: Running" -ForegroundColor Yellow
        } elseif ($servicio.Status -eq 'Stopped') {
            Write-Host "Estado del servicio: Stopped" -ForegroundColor DarkYellow
        } else {
            Write-Host "Estado del servicio: $($servicio.Status)"
        }
    } else {
        Write-Host "El servicio $ServicioNombre no está presente en el sistema."
    }

    Write-Host ""
}

Write-Host "Verificando el estado de los servicios:" -ForegroundColor DarkCyan
Write-Host
VerificarEstadoServicio -ServicioNombre "DPS" -ForegroundColor Yellow
VerificarEstadoServicio -ServicioNombre "SYSMAIN" -ForegroundColor Yellow
VerificarEstadoServicio -ServicioNombre "BAM" -ForegroundColor Yellow
VerificarEstadoServicio -ServicioNombre "APPINFO" -ForegroundColor Yellow
VerificarEstadoServicio -ServicioNombre "EVENTLOG" -ForegroundColor Yellow
VerificarEstadoServicio -ServicioNombre "dusmsvc" -ForegroundColor Yellow
VerificarEstadoServicio -ServicioNombre "pcasvc" -ForegroundColor Yellow
Write-Host

Write-Host "Searching Vpn....." -ForegroundColor Red
Write-Host

LoadingAnimation

function Check-VPNConnection {
    
    $networkInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }


    $vpnInterfaceNames = @("TAP-Windows Adapter V9", "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows", "OpenVPN TAP-Windows6 Adapter")


    $vpnDetected = $false
    foreach ($interface in $networkInterfaces) {
        if ($vpnInterfaceNames -contains $interface.Name) {
            $vpnDetected = $true
            Write-Host "Se ha detectado una conexión VPN en la interfaz: $($interface.Name)"
           
        }
    }

    if (-not $vpnDetected) {
        Write-Host "No se ha detectado ninguna conexión VPN."
    }
}

Check-VPNConnection

Write-host "Bam Entries....." -ForegroundColor DarkYellow

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

LoadingAnimation

Clear-Host

if ((Get-AuthenticodeSignature $MyInvocation.MyCommand.Path).Status -ne "Valid")
{

$check = [System.Windows.Forms.MessageBox]::Show($this, "WARNING:`n$(Split-path $MyInvocation.MyCommand.Path -Leaf) has been modified since it was signed.`nPress 'YES' to Continue or 'No' to Exit", "Warning", 'YESNO', 48)
switch ($check)
{
"YES"{ Continue }
"NO"{ Exit }
}
}
$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
    Try{New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE}
    Catch{"Error Mounting HKEY_Local_Machine"}
}
$bv = ("bam", "bam\State")
Try{$Users = foreach($ii in $bv){Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName}}
Catch{
    "Error Parsing BAM Key. Likely unsupported Windows Version"
    exit
}
$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias


$Bam = Foreach ($Sid in $Users){$u++
            
        foreach($rp in $rpath){
           Write-Progress -id 1 -Activity "$($rp)"
           $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
           Write-Progress -id 2 -Activity "Collecting Security ID (sid) entries" -Status "($($Users.Count)) sid: $($objSID.value)" -ParentId 1 
           $bi = 0 
    
            Try{
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate( [System.Security.Principal.NTAccount]) 
            $User = $User.Value
            }
            Catch{$User=""}
            $i=0
            ForEach ($Item in $BamItems){$i++
    $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue| Select-Object -ExpandProperty $Item
            Write-Progress -id 3 -Activity "Collecting BAM entries for SID: $($objSID.value)" -Status "(Entry $i of $($BamItems.Count))"  -ParentId 1 

            If($key.length -eq 24){
                $Hex=[System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format o
    $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format u
    $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
    $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2)) 
    $Biasd = $Bias/60
    $Dayd = $Day/60
    $TImeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format s) 
    $d = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
    {((split-path -path $item).Remove(23)).trimstart("\Device\HarddiskVolume")} else {$d = ""}
    $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
    {Split-path -leaf ($item).TrimStart()} else {$item}
    $cp = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
    {($item).Remove(1,23)} else {$cp = ""}
    $path = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
    {"(Vol"+$d+") "+$cp} else {$path = ""}

                [PSCustomObject]@{
                            'Examiner Time' = $TimeLocal
    'Last Execution Time (UTC)'= $TimeUTC
    'Last Execution User Time' = $TimeUser
     Application = $f
     Path =  $path
     User =         $User
     Sid =          $Sid
                             rpath =        $rp
                             }}}}
                 }
             
           

$Bam|Out-GridView -PassThru -Title "BAM key entries $($Bam.count)  - User TimeZone: ($UserTime) -> ActiveBias: ( $Bias) - DayLightTime: ($Day)"

$sw.stop()
$t=$sw.Elapsed.TotalMinutes
write-host "Elapsed Time $t minutes"
        
    }
    default {
        Write-Host "Opción no válida. Por favor, elige 1 o 2."
    }
}
