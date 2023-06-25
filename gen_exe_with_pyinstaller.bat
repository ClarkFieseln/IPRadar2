python updateRequirements.py
xcopy /y "requirements.txt" "dist\requirements.txt"
pip install -r requirements.txt
pip uninstall -y typing
pyinstaller IPRadar2.spec
pause
