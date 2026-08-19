@echo off
setlocal
set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo [ERROR] .NET Framework 4.8 C# compiler was not found.
  exit /b 1
)
if not exist "bin" mkdir "bin"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\GenerateIcon.ps1
if errorlevel 1 exit /b 1
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /win32icon:assets\PdfPasswordRecovery.ico /resource:assets\PdfPasswordRecovery.ico,PdfPasswordRecovery.AppIcon /out:bin\PdfPasswordRecovery.exe /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Runtime.Serialization.dll /reference:System.Windows.Forms.dll src\*.cs
if errorlevel 1 exit /b 1
echo Built bin\PdfPasswordRecovery.exe
