@echo off
REM Start SecureMailScope on Windows. Double-click this file.
REM
REM Creates a local virtual environment on first run, installs dependencies
REM into it, starts the server and opens a browser. Nothing is installed
REM system-wide and nothing outside this folder is touched.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set PORT=8000
set VENV=.venv

REM --- find a usable Python --------------------------------------------------
set PY=
for %%C in (py python python3) do (
  if not defined PY (
    %%C -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
    if !errorlevel! equ 0 set PY=%%C
  )
)

if not defined PY (
  echo.
  echo   Python 3.10 or newer is needed and was not found.
  echo   Install it from https://www.python.org/downloads/
  echo   During install, tick "Add Python to PATH", then run this file again.
  echo.
  pause
  exit /b 1
)

for /f "delims=" %%V in ('%PY% --version') do echo   Using %%V

REM --- set up the environment once -------------------------------------------
if not exist "%VENV%" (
  echo.
  echo   First run: creating a local environment ^(about a minute^)...
  %PY% -m venv "%VENV%"
)

call "%VENV%\Scripts\activate.bat"

python -c "import fastapi, dns, reportlab" >nul 2>&1
if errorlevel 1 (
  echo   Installing dependencies. This needs internet and takes a minute...
  python -m pip install --upgrade pip --quiet --retries 5 --timeout 60
  python -m pip install -r requirements.txt --quiet --retries 5 --timeout 60
  python -c "import fastapi, dns, reportlab" >nul 2>&1
  if errorlevel 1 (
    echo.
    echo   The install did not finish, usually a slow or blocked connection.
    echo   Check your internet and run this file again. It resumes rather
    echo   than starting over.
    echo.
    pause
    exit /b 1
  )
)

echo.
echo   Starting SecureMailScope on http://127.0.0.1:%PORT%
echo   Close this window to stop it.
echo.

start "" http://127.0.0.1:%PORT%
python -m uvicorn app.main:app --host 127.0.0.1 --port %PORT%

pause
