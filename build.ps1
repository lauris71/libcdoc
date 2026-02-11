#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libcdoc = $PSScriptRoot,
  [string]$platform = $env:PLATFORM,
  [string]$build_number = $(if ($null -eq $env:BUILD_NUMBER) {"0"} else {$env:BUILD_NUMBER}),
  [string]$msiversion = "1.0.0.$build_number",
  [string]$msi_name = "libcdoc-$msiversion$env:VER_SUFFIX.$platform.msi",
  [string]$git = "git.exe",
  [string]$vcpkg = "vcpkg\vcpkg.exe",
  [string]$vcpkg_dir = (split-path -parent $vcpkg),
  [string]$vcpkg_installed = $libcdoc,
  [string]$vcpkg_installed_platform = "$vcpkg_installed\vcpkg_installed_$platform",
  [string]$vcpkg_triplet = "$platform-windows",
  [string]$cmake = "cmake.exe",
  [string]$generator = "NMake Makefiles",
  [switch]$run_tests = $false,
  [string]$swig = $null,
  [string]$doxygen = $null,
  [string]$python = $null
)

Try {
  & wix > $null
}
Catch {
  & dotnet tool install -g --version 6.0.2 wix
  & wix extension add -g WixToolset.UI.wixext/6.0.2
}

if(!(Test-Path -Path $vcpkg)) {
  & $git clone https://github.com/microsoft/vcpkg.git $vcpkg_dir
  & $vcpkg_dir\bootstrap-vcpkg.bat
}

$cmakeext = @()
$wixext = @()
$target = @("all")
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
  $wixext += "-d", "swig=$swig"
}
if($doxygen) {
  $cmakeext += "-DDOXYGEN_EXECUTABLE=$doxygen"
}
if($platform -eq "arm64" -and $env:VSCMD_ARG_HOST_ARCH -ne "arm64") {
  $run_tests = $false
}
if($run_tests) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
  $target += "check"
}
if($python) {
  $cmakeext += "-DPython3_ROOT_DIR=$python/$platform"
  $wixext += "-d", "python=1"
}

foreach($type in @("Debug", "RelWithDebInfo")) {
  "==================="
  "Build Configuration: " + $type
  "==================="
  $buildpath = $platform+$type
  & $cmake --fresh -B $buildpath -S . "-G$generator" $cmakeext `
    "-DCMAKE_BUILD_TYPE=$type" `
    "-DCMAKE_INSTALL_PREFIX=$platform" `
    "-DCMAKE_INSTALL_BINDIR=." `
    "-DCMAKE_INSTALL_LIBDIR=." `
    "-DCMAKE_TOOLCHAIN_FILE=$vcpkg_dir/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_INSTALLED_DIR=$vcpkg_installed_platform" `
    "-DVCPKG_TARGET_TRIPLET=$vcpkg_triplet"
  & $cmake --build $buildpath --target $target
  & $cmake --install $buildpath
}

$docLocation = "$(Get-Location)/$platform/share/doc/libcdoc"
if (Test-Path -Path $docLocation -PathType Container) {
  $wixext += "-d", "docLocation=$docLocation"
}

& wix build -nologo -arch $platform -out $msi_name $wixext `
  -ext WixToolset.UI.wixext `
  -bv "WixUIBannerBmp=$libcdoc/banner.bmp" `
  -bv "WixUIDialogBmp=$libcdoc/dlgbmp.bmp" `
  -d "ICON=$libcdoc/ID.ico" `
  -d "vcpkg=$vcpkg_installed_platform/$vcpkg_triplet" `
  -d "libcdoc=$(Get-Location)/$platform" `
  $libcdoc\libcdoc.wxs

