@echo off
REM nmapParser 런처 - 더블클릭으로 GUI 실행
cd /d "%~dp0"
where pythonw >nul 2>&1
if %ERRORLEVEL%==0 (
    start "" pythonw "%~dp0nmapParser.py"
) else (
    where python >nul 2>&1
    if %ERRORLEVEL%==0 (
        start "" python "%~dp0nmapParser.py"
    ) else (
        echo.
        echo [오류] Python 이 설치되어 있지 않거나 PATH 에 없습니다.
        echo https://www.python.org/downloads/ 에서 Python 3.x 를 설치하세요.
        echo 설치할 때 "Add python.exe to PATH" 옵션을 꼭 켜세요.
        echo.
        pause
    )
)
