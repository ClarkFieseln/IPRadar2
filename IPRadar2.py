# Note: dont remove the following comment. Its for translation:
# -*- coding: utf-8 -*-
###############################

# imports
######
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
from ui.mainWindow import MainWindow
import sys
import configuration
import admin

# output shell to out_DATE.txt ?
if configuration.SHELL_TO_FILE == True:
    sys.stdout = open("Output/out_"+configuration.START_TIME+".txt", 'a', encoding="utf-8")
    sys.stderr = open("Output/out_"+configuration.START_TIME+".txt", 'a', encoding="utf-8")

####################
# main
####################    
if __name__ == "__main__":
    ######################
    if configuration.RUN_AS_ADMIN:
        # TODO: check/improve tool behavior when Admin.
        # When running as Admin we get a console
        # very strange behavior...we start a complete new instance of the App
        # we cannot debug when running as Admin.
        #########################
        if not admin.isUserAdmin():
            sys.exit(admin.runAsAdmin(cmdLine=None, wait=False))
            app = QApplication(sys.argv)
            font = QFont()
            font.setPointSize(configuration.FONT_SIZE)
            app.setFont(font) 
            ui = MainWindow()
            ui.show()
            sys.exit(app.exec_())
    ####################
    app = QApplication(sys.argv)
    font = QFont()
    font.setPointSize(configuration.FONT_SIZE)
    app.setFont(font) 
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())
    

