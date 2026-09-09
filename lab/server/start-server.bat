@echo off
setlocal
set "MINIPAY_CERT=%~dp0cert.pem"
set "MINIPAY_KEY=%~dp0key.pem"
"%~dp0MiniPay-Lab-Server.exe"
pause
