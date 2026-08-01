@echo off
setlocal
if not exist build-windows mkdir build-windows
cmake -S . -B build-windows
if errorlevel 1 exit /b 1
cmake --build build-windows --config Release
if errorlevel 1 exit /b 1
ctest --test-dir build-windows -C Release --output-on-failure
