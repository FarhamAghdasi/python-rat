@echo off
echo Deleting all __pycache__ folders...

for /d /r %%i in (__pycache__) do (
    if exist "%%i" (
        echo Deleting: %%i
        rmdir /s /q "%%i"
    )
)

echo Done.
pause
