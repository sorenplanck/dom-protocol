@echo off
setlocal ENABLEDELAYEDEXPANSION

echo ================================================
echo DOM Protocol Windows Portable Runners Installer
echo ================================================

after_copy:
set "SRC_DIR=%~dp0"
set "BIN_DIR=%LOCALAPPDATA%\DomProtocol\bin"

if not exist "%BIN_DIR%" (
  mkdir "%BIN_DIR%"
  if errorlevel 1 (
    echo [FAIL] Could not create %BIN_DIR%
    exit /b 1
  )
)

set "COPIED_ANY=0"
if exist "%SRC_DIR%dom-test-runner.exe" (
  copy /Y "%SRC_DIR%dom-test-runner.exe" "%BIN_DIR%\dom-test-runner.exe" >nul
  if errorlevel 1 (
    echo [FAIL] Could not copy dom-test-runner.exe
    exit /b 1
  )
  set "COPIED_ANY=1"
  echo [PASS] Installed dom-test-runner.exe
) else (
  echo [WARN] dom-test-runner.exe not found next to installer.
)

if exist "%SRC_DIR%dom-agent-runner.exe" (
  copy /Y "%SRC_DIR%dom-agent-runner.exe" "%BIN_DIR%\dom-agent-runner.exe" >nul
  if errorlevel 1 (
    echo [FAIL] Could not copy dom-agent-runner.exe
    exit /b 1
  )
  set "COPIED_ANY=1"
  echo [PASS] Installed dom-agent-runner.exe
) else (
  echo [WARN] dom-agent-runner.exe not found next to installer.
)

if "%COPIED_ANY%"=="0" (
  echo [FAIL] No runner executable found. Put this .bat next to .exe files and run again.
  exit /b 1
)

set "USER_PATH="
for /f "tokens=2,*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul ^| find /i "Path"') do set "USER_PATH=%%B"

echo %USER_PATH% | find /I "%BIN_DIR%" >nul
if errorlevel 1 (
  if defined USER_PATH (
    setx Path "%USER_PATH%;%BIN_DIR%" >nul
  ) else (
    setx Path "%BIN_DIR%" >nul
  )
  if errorlevel 1 (
    echo [FAIL] Could not update user PATH.
    exit /b 1
  )
  echo [PASS] Added %BIN_DIR% to your user PATH.
) else (
  echo [PASS] PATH already contains %BIN_DIR%.
)

echo.
echo Installation complete.
echo Open a NEW terminal and run:
echo   dom-test-runner.exe doctor
echo   dom-agent-runner.exe doctor
echo.
pause
exit /b 0
