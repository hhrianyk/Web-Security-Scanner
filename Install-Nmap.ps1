# Nmap Installation Script for PowerShell
# Run this script with administrative privileges for best results

function Test-NmapInstalled {
    $nmapPath = $null
    
    # Check if Nmap is in PATH
    try {
        $nmapPath = (Get-Command nmap -ErrorAction SilentlyContinue).Source
        if ($nmapPath) {
            $version = & nmap -V 2>&1
            Write-Host "Nmap already installed: $version" -ForegroundColor Green
            return $true
        }
    } catch {
        # Nmap not in PATH, continue checking
    }
    
    # Check common installation paths
    $commonPaths = @(
        "${env:ProgramFiles}\Nmap\nmap.exe", 
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $version = & $path -V 2>&1
            Write-Host "Nmap found at $path" -ForegroundColor Green
            Write-Host "   Version: $version" -ForegroundColor Green
            return $true
        }
    }
    
    Write-Host "Nmap not found on the system" -ForegroundColor Yellow
    return $false
}

function Install-Nmap {
    $tempFile = "$env:TEMP\nmap-setup.exe"
    $url = "https://nmap.org/dist/nmap-7.94-setup.exe"
    
    Write-Host "Downloading Nmap installer..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $url -OutFile $tempFile
    } catch {
        Write-Host "Error downloading Nmap: $_" -ForegroundColor Red
        Write-Host "Please download the installer manually from https://nmap.org/download.html" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "Installing Nmap..." -ForegroundColor Cyan
    Write-Host "Follow the installer instructions. It's recommended to install with default settings." -ForegroundColor Yellow
    
    try {
        Start-Process -FilePath $tempFile -Wait
        Write-Host "Installation completed!" -ForegroundColor Green
        
        # Clean up
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        
        return $true
    } catch {
        Write-Host "Error installing Nmap: $_" -ForegroundColor Red
        return $false
    }
}

function Install-PythonNmap {
    Write-Host "Installing python-nmap library..." -ForegroundColor Cyan
    try {
        & python -m pip install python-nmap
        Write-Host "python-nmap library installed successfully" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Error installing python-nmap library: $_" -ForegroundColor Red
        return $false
    }
}

function Add-NmapToPath {
    $nmapFound = $false
    $nmapPath = $null
    
    # Check common installation paths
    $commonPaths = @(
        "${env:ProgramFiles}\Nmap",
        "${env:ProgramFiles(x86)}\Nmap"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path "$path\nmap.exe") {
            $nmapPath = $path
            $nmapFound = $true
            break
        }
    }
    
    if (-not $nmapFound) {
        Write-Host "Could not find Nmap installation directory" -ForegroundColor Red
        return $false
    }
    
    Write-Host "Adding Nmap ($nmapPath) to PATH..." -ForegroundColor Cyan
    
    # Update PATH for current session
    $env:Path += ";$nmapPath"
    
    # Update PATH permanently
    try {
        # Add to system PATH (requires admin rights)
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if (-not $currentPath.Contains($nmapPath)) {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$nmapPath", "Machine")
            Write-Host "Nmap added to system PATH" -ForegroundColor Green
        } else {
            Write-Host "Nmap is already in PATH" -ForegroundColor Cyan
        }
        
        return $true
    } catch {
        try {
            # Add to user PATH as fallback
            $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if (-not $currentUserPath.Contains($nmapPath)) {
                [Environment]::SetEnvironmentVariable("Path", "$currentUserPath;$nmapPath", "User")
                Write-Host "Nmap added to user PATH" -ForegroundColor Green
            } else {
                Write-Host "Nmap is already in user PATH" -ForegroundColor Cyan
            }
            
            return $true
        } catch {
            Write-Host "Error adding Nmap to PATH: $_" -ForegroundColor Red
            Write-Host "Try running the script as Administrator" -ForegroundColor Yellow
            return $false
        }
    }
}

function Test-PythonNmap {
    Write-Host "Testing python-nmap library..." -ForegroundColor Cyan
    
    try {
        $result = & python -c "import nmap; print('OK')" 2>&1
        if ($result -eq "OK") {
            Write-Host "python-nmap library is working correctly" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Error importing python-nmap library" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "Error testing python-nmap library: $_" -ForegroundColor Red
        return $false
    }
}

# Main function
function Main {
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "   Nmap Installer for Windows (PowerShell)   " -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $isNmapInstalled = Test-NmapInstalled
    
    if (-not $isNmapInstalled) {
        $installChoice = Read-Host "Install Nmap? (y/n)"
        if ($installChoice -eq "y" -or $installChoice -eq "д") {
            $installResult = Install-Nmap
            if ($installResult) {
                # Re-check installation after setup
                $isNmapInstalled = Test-NmapInstalled
            }
        }
    }
    
    if ($isNmapInstalled) {
        $addToPathChoice = Read-Host "Add Nmap to PATH? (y/n)"
        if ($addToPathChoice -eq "y" -or $addToPathChoice -eq "д") {
            Add-NmapToPath
        }
        
        $installPythonChoice = Read-Host "Install python-nmap library? (y/n)"
        if ($installPythonChoice -eq "y" -or $installPythonChoice -eq "д") {
            Install-PythonNmap
            Test-PythonNmap
        }
    }
    
    Write-Host ""
    Write-Host "Script completed." -ForegroundColor Cyan
    Write-Host "After installing Nmap, it's recommended to restart your computer." -ForegroundColor Yellow
    
    if ($isNmapInstalled) {
        Write-Host ""
        Write-Host "To verify the installation after restart, run:" -ForegroundColor Cyan
        Write-Host "  nmap -V" -ForegroundColor Green
    }
}

# Run the main function
Main 