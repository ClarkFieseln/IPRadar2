# Note: don't remove the following comment. It's for translation:
# -*- coding: utf-8 -*-
###############################
from PyQt5.QtCore import pyqtSlot,  QFileInfo, QModelIndex, QThread, pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QListWidgetItem 
from PyQt5.QtGui import QColor, QFont 
from .Ui_mainWindow import Ui_MainWindow
from pysharkSniffer import pysharkSniffer
import shlex,  subprocess
from time import sleep,  gmtime,  strftime
import configuration
import admin
import os
from pathlib import Path
import threading
import ctypes

###################################
###################################
class MainWindow(QMainWindow, Ui_MainWindow):
    listOfHosts = []
    sniffer = pysharkSniffer()
    updateGuiThread = None
    fpath = "/"
    tsharkInterfaces = None
    tsharkInterfacesList = []
    currentInterface = None
    toggle = 0
    node_dict_gui = {} # complete dict of nodes
    item_index = {} # IP -> index
    indexCount = 0 # count item in self.listWidgetNodes
    status = ["/", "-", "\\", "|"]
    statusCnt = 0
    
    #############################
    # IMPORTANT: we don't modify GUI objects from a QThread
    #                     or even worse, from a python thread!!!
    #                     Instead, we send a signal to the GUI / MainWindow.
    # Ref.: https://stackoverflow.com/questions/12083034/pyqt-updating-gui-from-a-callback
    #############################
    class MyGuiUpdateThread(QThread):
        updated = pyqtSignal(str)

        def run( self ):
            while True:
                sleep(configuration.CHECK_PERIOD_IN_SEC*2.0)
                # TODO: improvement: pass e.g. time, counter or something useful to update function?
                self.updated.emit("Hi")
    #############################
    
    # thread to update GUI
    #############
    def updateGui(self):
        # update status on GUI
        ##############
        if self.lblStatus != None:
            # set alternating color
            if self.statusCnt%2:
                self.lblStatus.setStyleSheet('QLabel {background-color: ' + "lightgreen" + '; border: 1px solid black}')
            else:
                self.lblStatus.setStyleSheet('QLabel {background-color: ' + "lightgray" + '; border: 1px solid black}')
            # set alternating symbol
            self.lblStatus.setText(" "+self.status[self.statusCnt])
            self.statusCnt = (self.statusCnt + 1)%4
        
        # update counters
        ##########
        self.statusHostsRequested.setText(str(self.sniffer.getNumberOfHostsRequested()))
        self.statusHostsSolved.setText(str(self.sniffer.getNumberOfHostsSolved()))
        self.statusHostsFailed.setText(str(self.sniffer.getNumberOfHostsFailed()))
        self.statusConnections.setText(str(self.sniffer.getNumberOfConnections()))
        self.statusNodes.setText(str(self.sniffer.getNumberOfNodes()))
        self.statusBadNodes.setText(str(self.sniffer.getNumberOfBadNodes()))
        
        # nodes
        #####
        nodes = self.sniffer.getDictOfNodes()
        if nodes:
            for key, value in nodes.items():
                if key in self.node_dict_gui:
                    # update list with modified item
                    currIdx = self.item_index[key]
                    guiString = str(value)[str(value).find("pos")+4:]
                    self.listWidgetNodes.item(currIdx).setText(guiString)
                    ##################################
                    if value.killed == True:
                        self.listWidgetNodes.item(currIdx).setBackground(QColor('pink'))
                    elif value.local == True:
                        self.listWidgetNodes.item(currIdx).setBackground(QColor('lightblue')) # ('blue'))
                    elif value.bad == True:
                        self.listWidgetNodes.item(currIdx).setBackground(QColor('red')) # ('red'))
                    elif value.host_resolved == False:
                        self.listWidgetNodes.item(currIdx).setBackground(QColor('yellow'))
                    elif value.ping == False:
                        self.listWidgetNodes.item(currIdx).setBackground(QColor('lightyellow'))
                    else:
                        self.listWidgetNodes.item(currIdx).setBackground(QColor('lightgreen'))
                    ##################################
                    font = QFont()
                    if value.conn_established == True:
                        font.setBold(True)
                    else:
                        font.setBold(False)
                    self.listWidgetNodes.item(currIdx).setFont(font)
                    ##################################
                else:
                    # update list with new item
                    new_item = QListWidgetItem()
                    guiString = str(value)[str(value).find("pos")+4:]
                    new_item.setText(guiString)
                    ##################################
                    if value.killed == True:
                        new_item.setBackground(QColor('pink'))
                    elif value.local == True:
                        new_item.setBackground(QColor('lightblue')) # ('blue'))
                    elif value.bad == True:
                        new_item.setBackground(QColor('red')) # ('red'))
                    elif value.host_resolved == False:
                        new_item.setBackground(QColor('yellow'))
                    elif value.ping == False:
                        new_item.setBackground(QColor('lightyellow'))
                    else:
                        new_item.setBackground(QColor('lightgreen'))
                    ##################################
                    font = QFont()
                    if value.conn_established == True:
                        font.setBold(True)
                    else:
                        font.setBold(False)
                    new_item.setFont(font)
                    ##################################
                    self.listWidgetNodes.addItem(new_item)
                    ############
                    # auto-scroll
                    if configuration.AUTO_SCROLL_NODE_LIST:
                        self.listWidgetNodes.scrollToBottom()
                    ############
                    # store dict element: IP -> index to be able to access listWidgetNodes element using IP
                    self.item_index[key] = self.indexCount
                    self.indexCount = self.indexCount + 1
                    
                # new IPs added to combo-box
                #################
                if key not in self.node_dict_gui:
                    self.comboPing.addItem(key)    
                    # and select it..to show it..
                    # but only if IP selection option is NOT checked:
                    if self.cbPingIP.isChecked() == False:
                        self.comboPing.setCurrentIndex(self.comboPing.count()-1)
                # add/modify node to module dict
                self.node_dict_gui[key] = value
                
                # add new host (owner name) ?
                #################
                # find Owner Name:
                if str(value.whosip).find("Owner Name:") != -1:
                    startIndex = str(value.whosip).find("Owner Name:") + 14 
                    # find comma
                    endIndex = startIndex + str(value.whosip)[startIndex:].find(",")
                    hostTextFromOnwerName = str(value.whosip)[startIndex:endIndex]
                    if hostTextFromOnwerName not in self.listOfHosts:
                        self.listOfHosts.append(hostTextFromOnwerName)
                        self.comboShowHost.addItem(hostTextFromOnwerName)
                        # update text in GUI
                        self.comboShowHost.updateText()

            # create(update) report file
            ##################
            self.createReportFile()
            self.generateIps()
            
            # update combo-box with current connections
            #########################
            selectedIpTemp = str(self.comboKill.currentText())
            self.comboKill.clear()
            for key,  value in self.node_dict_gui.items():
                if value.conn_established:
                    self.comboKill.addItem(key)
                    # and select it..to show it..
                    # but only if IP selection option is NOT checked:
                    if (self.cbKillIP.isChecked() == False) or (key == selectedIpTemp):
                        self.comboKill.setCurrentIndex(self.comboKill.count()-1)
                        
        # killed nodes
        ########
        nrKilledNodes = self.sniffer.getNumberOfKilledNodes()
        ####################################
        if nrKilledNodes > self.listWidgetKilledProcesses.count():
            self.statusKilledNodes.setText(str(nrKilledNodes))
            listKilledNodes = self.sniffer.getListOfKilledNodes()
            for i in range(nrKilledNodes - self.listWidgetKilledProcesses.count()):
                new_item = QListWidgetItem()
                new_item.setText(listKilledNodes[nrKilledNodes-i-1])
                self.listWidgetKilledProcesses.addItem(new_item)
        ####################################    
        # TX max limit alarm handling
        #################
        txKiloBytes = self.sniffer.getNumberOfTxKiloBytes()
        if txKiloBytes > configuration.MAX_TX_KILOBYTES:
            if self.toggle == 0:
                self.statusTxBytes.setStyleSheet('color: red')
                self.labelTXBytes.setStyleSheet('color: red')
            else:
                self.statusTxBytes.setStyleSheet('color: black')
                self.labelTXBytes.setStyleSheet('color: black')
            self.toggle = not self.toggle
        self.statusTxBytes.setText(str(txKiloBytes))
        #################
        rxKiloBytes = str(self.sniffer.getNumberOfRxKiloBytes())
        self.statusRxBytes.setText(rxKiloBytes)

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        # fix size of window
        self.setFixedSize(self.size())
        #################
        currentTime = strftime("%Y.%m.%d %H:%M:%S", gmtime())
        adminStr = "Default user"
        if admin.isUserAdmin():
            adminStr = "Admin"
        self.setWindowTitle("IPRadar2 [" + currentTime + "] " + adminStr)
        
        # fill combo-box with tshark interfaces
        self.currentInterface = configuration.INTERFACE
        self.tsharkInterfaces = self.sniffer.getInterfaces()
        interfaceNr = 1
        for interface in self.tsharkInterfaces:
            self.comboBoxInterface.addItem(str(interfaceNr) + ". " + self.tsharkInterfaces[interface] + " " + interface)
            self.tsharkInterfacesList.append(interface)
            # is config IF? then set
            if self.currentInterface in interface:
                self.comboBoxInterface.setCurrentIndex(interfaceNr)
                self.comboBoxInterface.setCurrentText(str(interfaceNr) + ". " + self.tsharkInterfaces[interface] + " " + interface)
            interfaceNr = interfaceNr + 1
            
        # select default interface
        ########################
        if configuration.INTERFACE != "":
            # configured interface also selected?
            # if not set in combo-box
            if configuration.INTERFACE in self.comboBoxInterface.currentText():
                pass # config interface is same as selected
            else:
                index = self.comboBoxInterface.getCurrentIndex()
                self.currentInterface = self.tsharkInterfacesList[index]
        else:
            # default first interface
            self.currentInterface = self.tsharkInterfacesList[0]
            
        # set colors
        self.listWidgetKilledProcesses.setStyleSheet("background-color: lightGray")
        self.listWidgetKilledProcesses.setSelectionMode(self.listWidgetKilledProcesses.SingleSelection)
        self.listWidgetNodes.setStyleSheet("background-color: lightGray")
        self.listWidgetNodes.setSelectionMode(self.listWidgetNodes.SingleSelection)
        self.ptSelectedIP.setStyleSheet("background-color: lightGray")
        self.comboShowHost.setStyleSheet("background-color: lightGray")
        
        # init states
        ########
        self.comboShowHost.addItem("")
        self.pbKill.setEnabled(False)
        self.pbPing.setEnabled(False)
        self.pbToggleBounce.setChecked(configuration.BOUNCE)
        self.pbToggleHeatmap.setChecked(configuration.HEATMAP)
        self.cbShowBad.setChecked(configuration.SHOW_HOST_BAD)
        self.cbShowKilled.setChecked(configuration.SHOW_HOST_KILLED)
        self.cbShowMarkers.setChecked(configuration.SHOW_NODES)
        self.cbShowConnections.setChecked(configuration.SHOW_CONNECTIONS)
        self.cbShowConnectionsActive.setChecked(configuration.SHOW_CONNECTIONS_ACTIVE)
        self.cbShowInfo.setChecked(configuration.SHOW_INFO)
        self.cbShowGood.setChecked(configuration.SHOW_HOST_GOOD)
        self.cbShowUnresolved.setChecked(configuration.SHOW_HOST_UNKNOWN)
        self.cbShowBadConn.setChecked(configuration.SHOW_CONNECTION_BAD)
        self.cbShowKilledConn.setChecked(configuration.SHOW_CONNECTION_KILLED)
        self.cbShowGoodConn.setChecked(configuration.SHOW_CONNECTION_GOOD)
        self.cbShowUnresolvedConn.setChecked(configuration.SHOW_CONNECTION_UNKNOWN)
        self.cbPlot.setChecked(configuration.PLOT)
        self.cbSound.setChecked(configuration.SOUND)
        self.cbKillBad.setChecked(False)
        self.cbShowPing.setChecked(True)
        self.sniffer.pingAuto(self.cbPingAuto.isChecked())
        self.cbPingIP.setChecked(True)
        self.cbKillIP.setChecked(True)
        self.cbAutoScrollNodes.setChecked(configuration.AUTO_SCROLL_NODE_LIST)
        self.statusHostsFailedOld.setText(str(self.sniffer.getHostsFailedPast()))
        self.statusHostsResolvedOld.setText(str(self.sniffer.getHostsResolvedPast()))
        self.ptSelectedIP.textCursor().setKeepPositionOnInsert(True)
        self.cbPingRandom.setText(str(configuration.NR_OF_RANDOM_IPS_TO_PING)+" random IPs")
        self.cbBlockBadInFirewall.setChecked(configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP)
        # if not Admin we disable firewall rule option
        if configuration.RUN_AS_ADMIN == False:
            self.cbBlockBadInFirewall.setEnabled(False)
        
        #################
        # to upate GUI perdiodically
        #################
        self._thread = self.MyGuiUpdateThread(self)
        self._thread .updated.connect(self.updateGui)
        self._thread.start()
        
    def createReportFile(self):
        reportFileString = './Output/report_'+configuration.START_TIME+'.csv'
        reportFile = None
        try:
            reportFile = open(reportFileString, "w", encoding="utf-8")
            for itemIndex in range(self.listWidgetNodes.count()):
                reportFile.write(self.listWidgetNodes.item(itemIndex).text()+"\n")
            reportFile.write("\n")
            reportFile.close()
            print("Created Report File.")
        except Exception as e:
            if reportFile != None:
                reportFile.close()
            print("Exception: mainWindow.createReportFile() exception = ",  e)

    @pyqtSlot()
    def on_pushButton_clicked(self):
        if self.pushButton.text() == "exit":
            print("\nKill dumpcap and tshark")
            p1 = subprocess.Popen(shlex.split("taskkill /f /im dumpcap.exe"))
            p1.wait()
            p1.terminate()
            p1.kill()
            ##########
            p2 = subprocess.Popen(shlex.split("taskkill /f /im tshark.exe"))
            p2.wait()
            p2.terminate()
            p2.kill()
            ##########
            self.createReportFile()
            self.generateIps()
            #################
            currentTime = strftime("%Y.%m.%d %H:%M:%S", gmtime())
            self.setWindowTitle("IPRadar2 - capture finished on " + currentTime)
            print("Bye!")
            self.close()
        else:
            self.pbOpenFile.setEnabled(False)
            self.comboBoxInterface.setEnabled(False)
            self.sniffer.sniff(self.currentInterface)
            # deactivate button
            # TODO: improvement: implement live capture on/off
            self.pushButton.setText("exit")
            self.pbKill.setEnabled(True)
            self.pbPing.setEnabled(True)
            #################
            currentTime = strftime("%Y.%m.%d %H:%M:%S", gmtime())
            self.setWindowTitle("IPRadar2 - capture started on " + currentTime)
            
    @pyqtSlot()
    def on_pbOpenFile_clicked(self):
        if self.pbOpenFile.text() == "exit":
            print("\nKill dumpcap and tshark")
            p1 = subprocess.Popen(shlex.split("taskkill /f /im dumpcap.exe"))
            p1.wait()
            p1.terminate()
            p1.kill()
            ##########
            p2 = subprocess.Popen(shlex.split("taskkill /f /im tshark.exe"))
            p2.wait()
            p2.terminate()
            p2.kill()
            ##########
            self.createReportFile()
            print("Bye!")
            self.close()
        else:
            self.pushButton.setEnabled(False)
            self.pbOpenFile.setEnabled(False)
            self.comboBoxInterface.setEnabled(False)
            self.pbOpenFile.setText("processing..")
            fname = QFileDialog.getOpenFileName(self, 'Open file', 
                    self.fpath, "Packet capture file (*.pcapng *.pcap *.cap)")
            if len(fname) != 0:
                fname = fname[0]
                fileNameInfo = QFileInfo(fname)
                self.fpath = fileNameInfo.absolutePath() # use same dir in next call
                self.sniffer.sniff(0,  fname)
            self.pbOpenFile.setEnabled(True)
            self.pbOpenFile.setText("open file")
    
    @pyqtSlot()
    def on_pbSwitchMap_clicked(self):
        mapTypeString = self.sniffer.switchMap()
        self.pbSwitchMap.setText("Map: "+mapTypeString)
    
    @pyqtSlot()
    def on_pbToggleBounce_clicked(self):
        # Note: this returns string ON or OFF but is not used
        self.sniffer.toggleBounce()
    
    @pyqtSlot()
    def on_pbToggleHeatmap_clicked(self):
        # Note: this returns string ON or OFF but is not used
        self.sniffer.toggleHeatmap()
    
    @pyqtSlot()
    def on_cbShowBad_clicked(self):
        self.sniffer.toggleShowBadHosts()
    
    @pyqtSlot()
    def on_cbShowMarkers_clicked(self):
        self.sniffer.toggleShowNodes()
    
    @pyqtSlot()
    def on_cbShowConnections_clicked(self):
        self.sniffer.toggleShowConnections()
    
    @pyqtSlot()
    def on_cbShowInfo_clicked(self):
        self.sniffer.toggleShowInfo()
    
    @pyqtSlot()
    def on_cbShowGood_clicked(self):
        self.sniffer.toggleShowGoodHosts()
    
    @pyqtSlot()
    def on_cbShowUnresolved_clicked(self):
        self.sniffer.toggleShowUnknownHosts()
    
    @pyqtSlot()
    def on_cbShowGoodConn_clicked(self):
        self.sniffer.toggleShowGoodConnections()
    
    @pyqtSlot()
    def on_cbShowUnresolvedConn_clicked(self):
        self.sniffer.toggleShowUnknownConnections()
    
    @pyqtSlot()
    def on_cbShowBadConn_clicked(self):
        self.sniffer.toggleShowBadConnections()
    
    @pyqtSlot()
    def on_centralWidget_destroyed(self):
        print("mainWindow destroyed!")
        
    @pyqtSlot()
    def closeEvent(self,event):
        print("mainWindow closing..")
        self.on_pushButton_clicked()
    
    @pyqtSlot()
    def on_cbPlot_clicked(self):
        self.sniffer.setPlot(self.cbPlot.isChecked())
    
    @pyqtSlot()
    def on_cbSound_clicked(self):
        self.sniffer.setSound(self.cbSound.isChecked())
    
    @pyqtSlot(str)
    def on_comboBoxInterface_currentIndexChanged(self, p0):
        selectedIF = self.comboBoxInterface.currentIndex()
        # set IF
        if selectedIF != 0:
            self.currentInterface = self.tsharkInterfacesList[selectedIF]
            print("Selected tshark IF = ",  self.currentInterface)

    ##########################
    # change SETTINGS for killing automatically
    ##########################
    def killSetting(self):
        # change settings for killing automatically
        if self.cbKillBad.isChecked():
            # kill connections to bad IPs
            self.sniffer.killIPs()
        elif self.cbKillAll.isChecked():
            # kill all active connections
            self.sniffer.killAll()
        elif self.cbKillBandwidth.isChecked():
            # TODO: new feature: implement it..
            pass 
        elif self.cbKillNone.isChecked():
            # dont kill no one
            self.sniffer.killNone()
            
    @pyqtSlot()
    def on_cbKillNone_clicked(self):
        self.killSetting()
        self.cbKillBad.setStyleSheet('color: black')
        self.cbKillBandwidth.setStyleSheet('color: black')
        self.cbKillAll.setStyleSheet('color: black')
        
    @pyqtSlot()
    def on_cbKillBad_clicked(self):
        self.killSetting()
        self.cbKillBad.setStyleSheet('color: red')
        self.cbKillBandwidth.setStyleSheet('color: black')
        self.cbKillAll.setStyleSheet('color: black')
        
    @pyqtSlot()
    def on_cbKillBandwidth_clicked(self):
        self.killSetting()
        self.cbKillBad.setStyleSheet('color: black')
        self.cbKillBandwidth.setStyleSheet('color: red')
        self.cbKillAll.setStyleSheet('color: black')
        
    @pyqtSlot()
    def on_cbKillAll_clicked(self):
        self.killSetting()
        self.cbKillBad.setStyleSheet('color: black')
        self.cbKillBandwidth.setStyleSheet('color: black')
        self.cbKillAll.setStyleSheet('color: red')
    
    @pyqtSlot()
    def on_cbShowConnectionsActive_clicked(self):
        self.sniffer.toggleShowConnectionsActive()
    
    @pyqtSlot()
    def on_pbGenerateReport_clicked(self):
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        reportFileString = os.path.join(currAbsPath, currAbsPath+"\\Output\\report_"+configuration.START_TIME+".csv")
        if os.path.isfile(reportFileString):
            self.createReportFile()
            os.startfile(reportFileString)
        else:
            ctypes.windll.user32.MessageBoxW(0, "Report file not created.", "Warning: no data available yet!", 0)
        return
    
    @pyqtSlot()
    def on_cbPingAll_clicked(self):
        self.cbPingRandom.setStyleSheet('color: black')
        
    @pyqtSlot()
    def on_cbPingRandom_clicked(self):
        # set color red/black on GUI
        if self.cbPingRandom.isChecked():
            self.cbPingRandom.setStyleSheet('color: red')
        else:
            self.cbPingRandom.setStyleSheet('color: black')
            
    @pyqtSlot()
    def on_cbPingIP_clicked(self):
        self.cbPingRandom.setStyleSheet('color: black')
        
    def PingAllThread(self):
        self.sniffer.pingAll()
        
    def PingRandomThread(self):
        self.sniffer.pingRandom()
    
    @pyqtSlot()
    def on_pbPing_clicked(self):
        # ping All
        if self.cbPingAll.isChecked():
            # we call self.sniffer.pingAll() in a separate thread
            pingAllThread = threading.Thread(name="pingAllThread", target=self.PingAllThread)
            pingAllThread.start()
        # ping NR_OF_RANDOM_IPS_TO_PING random IPs:
        elif self.cbPingRandom.isChecked():
            if self.cbBlockBadInFirewall.isChecked():
                ##  Styles (4th argument of MessageBoxW()):
                ##  0 : OK
                ##  1 : OK | Cancel
                ##  2 : Abort | Retry | Ignore
                ##  3 : Yes | No | Cancel
                ##  4 : Yes | No
                ##  5 : Retry | No 
                ##  6 : Cancel | Try Again | Continue
                doReturn = ctypes.windll.user32.MessageBoxW(0, "If bad IPs are pinged, they will be added to the firewall, are you sure you want to proceed?", "Warning! Firewall rule may be added automatically.", 1)
                # OK == 1, Cancel == 2
                if doReturn == 2:
                    return
            # we call self.sniffer.pingRandom() in a separate thread
            pingRandomThread = threading.Thread(name="pingRandomThread", target=self.PingRandomThread)
            pingRandomThread.start()
        # ping selected IP:
        else:
            if self.comboPing.currentText() != "":
                self.sniffer.pingIP(self.comboPing.currentText())
    
    @pyqtSlot()
    def on_cbPingAuto_clicked(self):
        self.sniffer.pingAuto(self.cbPingAuto.isChecked())
    
    @pyqtSlot()
    def on_cbShowPing_clicked(self):
        self.sniffer.toggleShowPingedNegHosts()
    
    @pyqtSlot(str)
    def on_comboPing_currentIndexChanged(self, p0):
        # dont do anything for now..
        return
    
    ##########
    # kill COMMAND
    ##########
    @pyqtSlot()
    def on_pbKill_clicked(self):
        if self.cbKillAllNow.isChecked():
            # active connections
            self.sniffer.killAllNow()
        elif self.cbKillBadNow.isChecked():
            # connections to bad IPs
            self.sniffer.killIPsNow()
        else:
            # connection to specified IP
            if self.comboKill.currentText() != "":
                self.sniffer.killIP(self.comboKill.currentText())
    
    @pyqtSlot()
    def on_cbShowKilled_clicked(self):
        self.sniffer.toggleShowKilledHosts()
    
    @pyqtSlot()
    def on_cbShowKilledConn_clicked(self):
        self.sniffer.toggleShowKilledConnections()
    
    @pyqtSlot(QListWidgetItem)
    def on_listWidgetNodes_itemClicked(self, item):
        self.ptSelectedIP.document().setPlainText(item.text().replace(",", "\n")) 
    
    @pyqtSlot()
    def on_listWidgetKilledProcesses_itemSelectionChanged(self):
        startiIx = self.listWidgetKilledProcesses.currentItem().text().find("(") + 1
        endiIx = self.listWidgetKilledProcesses.currentItem().text().find(")") # - 1
        ip = self.listWidgetKilledProcesses.currentItem().text()[startiIx:endiIx]
        if ip in self.item_index:
            self.listWidgetNodes.setCurrentItem(self.listWidgetNodes.item(self.item_index[ip]))
            self.ptSelectedIP.document().setPlainText(self.listWidgetNodes.item(self.item_index[ip]).text().replace(",", "\n")) 
            self.listWidgetNodes.scrollToItem(self.listWidgetNodes.item(self.item_index[ip]))
    
    @pyqtSlot(QModelIndex)
    def on_listWidgetKilledProcesses_clicked(self, index):
        self.on_listWidgetKilledProcesses_itemSelectionChanged()
    
    @pyqtSlot()
    def on_cbAutoScrollNodes_clicked(self):
        configuration.AUTO_SCROLL_NODE_LIST = self.cbAutoScrollNodes.isChecked()
    
    @pyqtSlot(str)
    def on_comboShowHost_currentTextChanged(self, p0):
        print("Owner Name CHANGED:")
        print(self.comboShowHost.currentData())
        s = set(self.comboShowHost.currentData())
        diff = [x for x in self.listOfHosts if x not in s]
        print("List of NOT found hosts = ",  diff)
        # update nodes
        self.sniffer.updateShowNotShowOwners(self.comboShowHost.currentData(), diff)
        # update text in GUI
        self.comboShowHost.updateText()
    
    @pyqtSlot()
    def on_cbBlockBadInFirewall_clicked(self):
        self.sniffer.setBlockBadInFirewall(self.cbBlockBadInFirewall.isChecked())
        # set color red/black on GUI
        if self.cbBlockBadInFirewall.isChecked():
            self.cbBlockBadInFirewall.setStyleSheet('color: red')
        else:
            self.cbBlockBadInFirewall.setStyleSheet('color: black')
    
    @pyqtSlot()
    def on_pbShowMap_clicked(self):
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        filename = os.path.join(currAbsPath, currAbsPath+"\\Output\\map_"+configuration.START_TIME+".html")
        if os.path.isfile(filename):
            os.startfile(filename)
        else:
            ctypes.windll.user32.MessageBoxW(0, "Map file not yet created.", "Warning: no .html file available!", 0)
    
    @pyqtSlot()
    def on_pbStartIpNetInfo_clicked(self):
        # NOTE: for now we dont avoid having many instances of ipnetinfo.exe
        #            if "ipnetinfo.exe" not in (p.name() for p in psutil.process_iter()):
        if self.indexCount != 0:
            ipNetInfoThread = threading.Thread(name="ipNetInfoThread", target=self.IpNetInfoThread)
            ipNetInfoThread.start()
        else:
            ctypes.windll.user32.MessageBoxW(0, "Host list is currently empty.", "Warning: no items available!", 0)
            
    def generateIps(self):
        # create ips.txt
        ip_file_name = "Output/ips_"+configuration.START_TIME+".txt"        
        f = open(ip_file_name, "w", encoding="utf-8")
        if self.rbSelectedIpInfos.isChecked():
            ip = configuration.PUBLIC_IP # default value
            if self.listWidgetNodes.currentItem() != None:
                txt = self.listWidgetNodes.currentItem().text() # long text
                txt = txt[0:txt.find(",")] # first item is the position (as string)
                index = int(txt) # make it an integer
                for key,  value in self.item_index.items():
                    if value == index:
                        ip = key
                f.write(ip + "\n")
            else:
                ctypes.windll.user32.MessageBoxW(0, "No item selected, please select a host.", "Warning: no item selected!", 0)
                return
        else:
            for ip in self.node_dict_gui:
                f.write(ip + "\n")
        f.close()

    def IpNetInfoThread(self):
        # create ips.txt     
        ip_file_name = "Output/ips_"+configuration.START_TIME+".txt"        
        f = open(ip_file_name, "w", encoding="utf-8")
        if self.rbSelectedIpInfos.isChecked():
            ip = configuration.PUBLIC_IP # default value
            if self.listWidgetNodes.currentItem() != None:
                txt = self.listWidgetNodes.currentItem().text() # long text
                txt = txt[0:txt.find(",")] # first item is the position (as string)
                index = int(txt) # make it an integer
                for key,  value in self.item_index.items():
                    if value == index:
                        ip = key
                f.write(ip + "\n")
            else:
                ctypes.windll.user32.MessageBoxW(0, "No item selected, please select a host.", "Warning: no item selected!", 0)
                return
        else:
            for ip in self.node_dict_gui:
                f.write(ip + "\n")
        f.close()
        # if executing IPRadar2.exe we'll get mainWindow.pyc instead of mainWindow.py
        runningScript = os.path.basename(__file__)
        # path
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        currAbsPath = currAbsPath.replace("\\", "/")
        # different relative paths depending if we debug or execute IPRadar2.exe
        if(runningScript=="mainWindow.py"): # .py script
            command = "\"" + currAbsPath + "/dist/ipnetinfo/ipnetinfo.exe\" /ipfile "+ip_file_name 
        # .exe file
        else: 
            command = "\"" + currAbsPath + "/ipnetinfo/ipnetinfo.exe\" /ipfile "+ip_file_name 
        # start ipnetinfo.exe
        p1 = subprocess.Popen(shlex.split(command), shell=True, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            pass
        else:
            print("Error: could not run ipnetinfo.exe!")
        ##########
        p1.terminate()
        p1.kill()
    
    @pyqtSlot()
    def on_rbAllIpInfos_clicked(self):
        return
    
    @pyqtSlot()
    def on_rbSelectedIpInfos_clicked(self):
        return
    







