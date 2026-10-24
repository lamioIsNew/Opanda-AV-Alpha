@echo off
cd /d C:\opanda_test
HipsClient.exe selftest > hips_selftest.txt 2>&1
