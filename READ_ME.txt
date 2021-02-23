Instructions to install IPRadar2 (2021.02.23): 

**************************************************************************************************
WARNING! 
some "defense" features may add new rules to your windows firewall or block network connections by killing processes automatically.
This is the reason why these features are deactivated per default.
If not properly configured, this tool may cause unforeseen system behavior.
Note: in case of problems firewall rules can be easily removed any time.
**************************************************************************************************

1) install eric6 IDE and all required dependencies (like PyQt5), check the file requirements.txt
    (configure your environment as required)
    
2) configure config.ini as required
     IMPORTANT: Note that the default values are just arbitrary and need to be adapted!
                                   Get familiar with the behavior of the tool before you set ADD_FIREWALL_RULE_BLOCK_BAD_IP to 1.
 
3) in folder /backups you find some files you need to replace in the corresponding installation paths:
    installation_path\Python37\Lib\site-packages\pyshark\capture\capture.py
    installation_path\Python37\Lib\site-packages\gmplot\gmplot.py # the interface has been extended!
    installation_path\Python37\Lib\site-packages\pyshark\tshark\tshark.py
    # installation_path/Python37/Lib/site-packages/PyQt5/ __init__.py # bug solved with new version, don't need to adapt

4) copy ipnetinfo into this folder:
      \myProject\dist\ipnetinfo
      (you can get it from here https://www.nirsoft.net/utils/ipnetinfo.html)

5) copy Whosip into this folder:
      \myProject\dist\WhosIP
      (you can get it from here https://www.nirsoft.net/utils/whosip.html)

6) install WiresharkPortable into this folder:
     \myProject\dist\WiresharkPortable
     (you can get it from here https://www.wireshark.org/download.html)
     (this version used: WiresharkPortable_3.2.3.paf)
     you need to install also Npcap - for that you need admin rights!
     (you can get it from here https://nmap.org/npcap/#download)
     (this version used: npcap-0.9990.exe)

7) in folder \myProject\dist\PyQt5\Qt\bin copy these files:
    Qt5Core.dll
    Qt5Gui.dll
    Qt5Widgets.dll
    you can get these files from here:
    installation_path\Python37\Lib\site-packages\PyQt5\Qt\bin

8) obtain the audio files as described in todo.txt found in folder Sounds.

9) for the next steps you shall check your antivirus settings.
     Some antiviruses may block IPRadar2. Make sure you add it to the exception list of your antivirus if required.
     You may need to do this during or after steps 9) and 10).
     In rare cases you may also need to check your firewall settings.

10) in Eric6, go to Project -> new Project 
     -> in project folder select the path with the sources 
     -> in main file select IPRadar2.py
     -> press OK
     -> IDE will ask something like "add existing files to project?"
     -> press YES, then OK 
     (do this only in case of problems: -> go to Forms tab, right-mouse-click on ui/mainWindow.ui -> translate Form)
     Press the button "Execute project", then hit OK

11) generate an executable file:
     double click on gen_exe_with_pyinstaller.bat
     (the generated file IPRadar2.exe will be inside folder /dist - you can now execute it)
     (note that there is an own config.ini file for the executable)
     (the folder dist/Sounds is empty, you can copy the files from one level above)

12) How to use tool: check the Code Project article IPRadar2:
    https://www.codeproject.com/Articles/5269206/IP-Radar-2


