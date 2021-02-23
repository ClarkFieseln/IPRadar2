@echo off
echo IPRadar2 starting... output to log.txt
REM SET PATH=%PATH%;%cd%;%cd%\WiresharkPortable\App\Wireshark;%cd%\PyQt5\Qt\bin
cmd.exe /c START /MIN /B IPRadar2.exe > log.txt
REM START /MIN /B IPRadar2.exe > log.txt
REM START /MIN IPRadar2.exe > log.txt
REM START IPRadar2.exe > log.txt
REM exit
@echo on
