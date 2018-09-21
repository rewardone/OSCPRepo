@echo off
REM Description: Script that queries all services and searches for exeuctables that give the Everyone group RW access.
REM Type: Incorrect file permissions
REM Note: The ^ characters escapes certain characters that brerak the FOR loop.
REM Note: tokens=1* - The value at the first delimeter and everything after. 
for /f "tokens=1*" %%m in ('sc query state^= all ^| find "SERVICE_NAME"') do (
    for /f "tokens=1* delims=: " %%r in ('sc qc "%%~n" ^| find "BINARY_PATH_NAME"') do (
        for /f "delims=" %%x in ('echo(%%~s^| findstr /L /V /I /C:"%SystemRoot%\System32" /C:"%SystemRoot%\SysWOW64"') do (
            icacls "%%~x"
        )
    )
)