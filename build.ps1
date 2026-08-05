#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libcdoc = $PSScriptRoot,
  [string]$platform = $(if ($null -eq $env:PLATFORM) {"x64"} else {$env:PLATFORM}),
  [string]$build_number = $(if ($null -eq $env:BUILD_NUMBER) {"0"} else {$env:BUILD_NUMBER}),
  [string]$git = "git.exe",
  [string]$vcpkg = $env:VCPKG_ROOT,
  [string]$cmake = "cmake.exe",
  [string]$generator = "Ninja Multi-Config",
  [string]$swig = $null,
  [string]$installdir = $null,
  [string[]]$buildType = @("Debug", "RelWithDebInfo"),
  [switch]$RunTests = $false
)

if(!$vcpkg -or !(Test-Path -Path $vcpkg)) {
  $vcpkg = "$libcdoc\vcpkg"
  & $git clone https://github.com/microsoft/vcpkg $vcpkg
  & $vcpkg\bootstrap-vcpkg.bat
}

$cmakeext = @()
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
}
if($RunTests) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
}
if($installdir) {
  $cmakeext += "-DCMAKE_INSTALL_PREFIX=$installdir"
}

$env:PLATFORM = $platform
$env:VCPKG_ROOT = $vcpkg

& $cmake --preset windows --fresh "-G$generator" $cmakeext

foreach($type in $buildType) {
    & $cmake --build --preset windows --config $type
    if($RunTests) {
        & $cmake --build --preset windows --config $type --target check
    }
    if($installdir) {
        & $cmake --build --preset windows --config $type --target install
    }
}
