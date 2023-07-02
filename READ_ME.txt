Instructions to install IPRadar2 (2023.07.02): 

**************************************************************************************************
WARNING! 
some "defense" features may add new rules to your windows firewall or block network connections by killing processes automatically.
This is the reason why these features are deactivated per default.
If not properly configured, this tool may cause unforeseen system behavior.
Note: in case of problems firewall rules can be easily removed any time.
**************************************************************************************************

1) Install PyCharm, you can get it here: 
          https://www.jetbrains.com/pycharm/
   copy the sources provided in GitHub or in CodeProject to some directory:
          GitHub: https://github.com/ClarkFieseln/IPRadar2
          CodeProject: https://www.codeproject.com/Articles/5269206/IP-Radar-2
   Open PyCharm, press the button New Project -> select the location of the folder with the sources copied in the previous step.
   (leave the default path to the virtual enviroment, which is inside your project folder (the new folder is called venv)).
   Select Python39 as the Base interpreter (a different interpeter may be selected, but you may need to adapt the dependencies later).
   Don't inherit global site-packages, I think it is cleaner if we only depend on the things we really need.
   We also don't need to make this new enviroment be available to all projects.

   You then get a Warning Message telling you that the "Directory is Not Empty" -> select "Create from Existing Sources"  (an .idea folder is created).
   
   The project path may need to be added to Microsoft Defender (select option Automatically in Warning-window at the bottom-right side).

   Go to Edit Configurations -> select "+" to add a new configuration  -> select Python -> call it IPRadar2.
   Select IPRadar2.py in Script path   ->  Press OK.

   Select "Install requirements" when the warning appears that some Package requiremetns are not fulfilled.
   (you then get a list, leave all checked, select Install).
   Check also related steps 7) and 8).
    
2) Configure config.ini as required
   IMPORTANT: Note that the default values are just arbitrary and need to be adapted!
              Get familiar with the behavior of the tool before you set ADD_FIREWALL_RULE_BLOCK_BAD_IP to 1.
 
3) Make a copy of the file \venv\Lib\site-packages\gmplot\gmplot.py 
   Then replace it with \backups\gmplot.py 
   Note: the interface has been extended.

4) Copy ipnetinfo into this folder:
      \myProject\dist\ipnetinfo
   You can get it from here https://www.nirsoft.net/utils/ipnetinfo.html

5) Copy Whosip into this folder:
      \myProject\dist\WhosIP
   You can get it from here https://www.nirsoft.net/utils/whosip.html

6) Install WiresharkPortable into this folder:
      \myProject\dist\WiresharkPortable
   You can get it from here https://www.wireshark.org/download.html
   You may also need to install also Npcap (optional step)
   You can get it from here https://nmap.org/npcap/#download

7) This step is ONLY needed e.g. if step 1) in PyCharm went wrong or a different interpreter is used:
    In your PyCharm project, open the Terminal inside PyCharm, make sure the the virtual environment is activated i.e. Terminal prompt starts with (venv)...
    Then type:
       pip install -r requirements.txt

8) Install required tools:    
    Type in the PyCharm console:
       pip install pyqt5 pyqt5-tools
       pip install pipreqs
    (optional: python -m pip install pywin32 (already covered at the end of 1)))
    See step 12)

9) Obtain the audio files as described in todo.txt found in folder Sounds.

10) Generate an executable file (in just a few seconds!): of size 56MB in my case..
   In the PyCharm Terminal type: 
      pip install pyinstaller
      .\gen_exe_with_pyinstaller.bat
      (alternatively, you may double click on gen_exe_with_pyinstaller.bat  

   The generated file IPRadar2.exe will be inside folder /dist
   Note that there is an own config.ini file for the executable that you also need to adapt.
   The folder dist/Sounds is empty, you can copy the files from the folder Sounds one level above.
   Now you can now execute the file IPRadar2.exe

11) Check the Code Project article IPRadar2 that explains how to use the tool:
       https://www.codeproject.com/Articles/5269206/IP-Radar-2

12) if you edit mainWindow.ui, e.g. with Qt Designer, then you can execute gen_py_from_ui.bat in your PyCharm terminal in order to update Ui_mainWindow.py.
    NOTE: in the following link you find a standalone Qt Designer which does not require downloading gigabytes of other software:
          https://build-system.fman.io/qt-designer-download


