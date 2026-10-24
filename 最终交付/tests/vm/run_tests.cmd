@echo off
setlocal
set SRC=%~dp0
set DST=C:\opanda_test
if not exist "%DST%" mkdir "%DST%"
xcopy "%SRC%*.*" "%DST%\" /Y /Q >nul
cd /d "%DST%"

echo ==== hw_probe (scanner.dll hardware API) ==== > results.txt
hw_probe.exe scanner.dll >> results.txt 2>&1
echo. >> results.txt
echo ==== pe_vm selftest (new MSVC build) ==== >> results.txt
pe_vm_msvc.exe --selftest >> results.txt 2>&1
echo. >> results.txt
echo ==== pe_vm JMP [IAT] test (new build) ==== >> results.txt
pe_vm_msvc.exe pevm_jmp_test.exe --trace pevm_jmp_new.trace.txt --max-insn 200000 >> results.txt 2>&1
echo. >> results.txt
echo ==== pe_vm JMP [IAT] test (old build, comparison) ==== >> results.txt
if exist pe_vm.exe pe_vm.exe pevm_jmp_test.exe --trace pevm_jmp_old.trace.txt --max-insn 200000 >> results.txt 2>&1
echo. >> results.txt
type results.txt
pause
