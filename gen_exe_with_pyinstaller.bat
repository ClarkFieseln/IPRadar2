python updateRequirements.py
pyinstaller --onefile IPRadar2.spec 
xcopy /y "requirements.txt" "dist\requirements.txt"
pause
