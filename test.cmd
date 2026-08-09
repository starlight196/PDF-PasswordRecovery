@echo off
setlocal
set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo [ERROR] .NET Framework 4.8 C# compiler was not found.
  exit /b 1
)
if not exist "bin" mkdir "bin"
"%CSC%" /nologo /target:exe /platform:x64 /optimize+ /out:bin\CryptoSelfTest.exe /reference:System.dll /reference:System.Core.dll src\PdfSecurity.cs src\DictionaryAttack.cs tests\CryptoSelfTest.cs
if errorlevel 1 exit /b 1
bin\CryptoSelfTest.exe
