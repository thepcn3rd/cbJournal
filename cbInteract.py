from threading import Thread
import cmd, time, os, pprint
import cbapi

SERVERURL = "https://172.16.0.154"
APITOKEN = "e917126683af622723eaed989b1f40defcf663af"

historyAll = []
historySizeRetention = 100
historyAlertSearch = []
historyProcessSearch = []
historyProcessEvents = []
historyBinarySearch = []

journalFile = "journal/journal-" + str(time.strftime("%m-%d-%Y"))

serverConnected = False
cbC = None              # Carbon Black Connection to API

def checkDirectories():
    if not (os.path.exists("history")):
        os.makedirs("history")
    if not (os.path.exists("journal")):
        os.makedirs("journal")
    if not (os.path.exists("temp")):
        os.makedirs("temp")

def connectServer():
    global serverConnected, cbC, SERVERURL, APITOKEN
    if serverConnected == False:
        cbC = cbapi.CbApi(SERVERURL, token=APITOKEN, ssl_verify=False)
        serverConnected = True
    elif serverConnected == True:
        print "If no results are returned check that your Server URL or API Token is configured."
    return

def searchCb(searchType, c):
    global cbC, historyAll, journalFile, SERVERURL, APITOKEN, historyProcessEvents
    if searchType == "processSearch":
        global historyProcessSearch
        historySearch = historyProcessSearch
    elif searchType == "binarySearch":
        global historyBinarySearch
        historySearch = historyBinarySearch
    elif searchType == "alertSearch":
        global historyAlertSearch
        historySearch = historyAlertSearch
    if c == "history":
        count = 1
        for i in historySearch:
            print str(count) + ": " + i
            count += 1
        print
    elif c == "help":
        if searchType == "alertSearch":
            print
            print "To query select a field below and place a colon after it and a keyword to search against."
            print "Like: alertSearch query alert_type:*   OR use abreviations..."
            print "Like: aS q alert_type:*"
            print '{:40} {:40}'.format("alert_severity:[40 TO *]", 'alert_type:"watchlist.hit.query.process"')
            print '{:40} {:40}'.format("assigned_to:a*", "created_time:[* TO 2016-02-02T23:59:59]")
            print '{:40} {:40}'.format("feed_name:e*", "group:W*")
            print '{:40} {:40}'.format("hostname:S*", "md5:712402*")
            print '{:40} {:40}'.format("os_type:w*", "process_name:p*")
            print '{:40} {:40}'.format("process_path:*temp*", "report_score:[75 TO *]")
            print '{:40} {:40}'.format("sensor_id:5", "status:Resolved")
            print '{:40} {:40}'.format("username:*t*", "watchlist_id:1")
            print '{:40}'.format("watchlist_name:P*")
            print 'Refer to the Cb documentation for additional search parameters.'
            print
        elif searchType == "processSearch":
            print
            print "To query select a field below and place a colon after it and a keyword to search against."
            print "Like: processSearch query group:W*   OR use abreviations..."
            print "Like: pS q group:W*"
            print '{:40} {:40}'.format("childproc_count:[1 TO *]","cmdline:*")
            print '{:40} {:40}'.format("crossproc_count:[1 TO *]", "filemod_count:[1 TO *]")
            print '{:40} {:40}'.format("group:W*", "hostname:S*")
            print '{:40} {:40}'.format("modload_count:[1 TO *]", "netconn_count:[1 TO *]")
            print '{:40} {:40}'.format("parent_md5:54321*", "parent_name:expl*")
            print '{:40} {:40}'.format("path:*temp*","process_md5:54321*")
            print '{:40} {:40}'.format("process_name:put*", "process_pid:3392")
            print '{:40} {:40}'.format("regmod_count:[5 TO *]", "sensor_id:5")
            print '{:40} {:40}'.format("start:[2016-05-04T23:59:59 TO *]", "username:l*")
            print 'Refer to the Cb documentation for additional search parameters.'
            print
        elif searchType == "binarySearch":
            print
            print "To query select a field below and place a colon after it and a keyword to search against."
            print "Like: binarySearch query alert_type:*   OR use abreviations..."
            print "Like: bS q alert_type:*"
            print '{:40} {:40}'.format("company_name:S*", "digsig_result:Unsigned")
            print '{:40} {:40}'.format("endpoint:S*", "file_desc:SSH*")
            print '{:40} {:40}'.format("file_version:R*", "group:W*")
            print '{:40} {:40}'.format("host_count:[0 TO 1]", "internal_name:P*")
            print '{:40} {:40}'.format("is_64bit:True", "is_executable_image:True")
            print '{:40} {:40}'.format("md5:5*", "observed_filename:putty")
            print '{:40} {:40}'.format("original_filename:P*", "signed:Unsigned")
            print 'Refer to the Cb documentation for additional search parameters.'
            print
    elif c.count(" ") >= 1:
        c = c.split(" ")
        if (c[0] == "query") or (c[0] == "q"):
            if (SERVERURL != None and APITOKEN != None):
                connectServer()
                start = 0
                pagesize = 10
                count = 1
                lastCommand = None
                historyProcessEvents = []
                while True:
                    j = open(journalFile, 'a')
                    try:
                        if len(c) > 2:
                            fullQuery = ""
                            for i in range(1, len(c)):
                                fullQuery += c[i] + " "
                            fullQuery = fullQuery[:-1]
                        else:
                            fullQuery = c[1]
                        if searchType == "alertSearch":
                            try:
                                results = cbC.alert_search(fullQuery, rows=int(pagesize), start=start)
                            except:
                                print "The following query did not work: " + fullQuery
                                break
                            j.write("\n\nAlert Search Query\n")
                        elif searchType == "processSearch":
                            try:
                                results = cbC.process_search(fullQuery, rows=int(pagesize), start=start)
                            except:
                                print "The following query did not work: " + fullQuery
                                break
                            j.write("\n\nProcess Search Query\n")
                        elif searchType == "binarySearch":
                            try:
                                results = cbC.binary_search(fullQuery, rows=int(pagesize), start=start)
                            except:
                                print "The following query did not work: " + fullQuery
                                break
                            j.write("\n\nBinary Search Query\n")
                    except:
                        print "Error with Search Query: " + c[1]
                        break
                    if len(results['results']) == 0:
                        print "No results were returned with the following query: " + fullQuery
                        break
                    if lastCommand != fullQuery:
                        displayQuery = searchType + " " + c[0] + " " + fullQuery
                        historyAll.append(displayQuery)
                        historySearch.append(displayQuery)
                        lastCommand = fullQuery
                    j.write(displayQuery + '\n')
                    for result in results['results']:
                        if searchType == "alertSearch":
                            displayAlert = str(count) + ": "
                            # Place the key fields in the order in which you want them to display
                            keyFields = ["alert_severity", "process_name", "created_time", "hostname", "md5", "username", "watchlist_name", "process_path"]
                            headerFields = ""
                            for keyField in keyFields:
                                headerFields += keyField + ", "
                            for keyField in keyFields:
                                if keyField in result:
                                    displayAlert += keyField + ":" + str(result[keyField]) + " "
                                else:
                                    displayAlert += ""
                        elif searchType == "processSearch":
                            displayAlert = str(count) + ": "
                            # Place the key fields in the order in which you want them to display
                            keyFields = ["hostname", "process_name", "filemod_count", "modload_count", "netconn_count", "regmod_count", "childproc_count","crossproc_count","group","parent_name","username", "start", "id", "segment_id", "path"]
                            headerFields = ""
                            for keyField in keyFields:
                                headerFields += keyField + ", "
                            for keyField in keyFields:
                                # Formatting of the output would be nice
                                if keyField in result:
                                    displayAlert += keyField + ":" + str(result[keyField]) + " "
                                else:
                                    displayAlert += " "
                            strProcessEvents = str(count) + "|" + str(result['id']) + "|" + str(result['segment_id']) + "|" + str(result['hostname']) + "|" + str(result['process_name'])
                            historyProcessEvents.append(strProcessEvents)
                            #pprint.pprint(result)
                        elif searchType == "binarySearch":
                            displayAlert = str(count) + ": "
                            # Place the key fields in the order in which you want them to display
                            keyFields = ["original_filename", "md5", "signed", "host_count", "group", "digsig_result", "company_name", "file_desc", "observed_filename", "is_executable_image","is_64bit"]
                            headerFields = ""
                            for keyField in keyFields:
                                headerFields += keyField + ", "
                            for keyField in keyFields:
                                # Formatting of the output would be nice
                                if keyField in result:
                                    displayAlert += keyField + ":" + str(result[keyField]) + " "
                                else:
                                    displayAlert += " "
                            #pprint.pprint(result)
                        print displayAlert
                        j.write(displayAlert + '\n')
                        count += 1
                    print headerFields[:-2]
                    j.write(headerFields[:-2])
                    retrieveMore = raw_input("Retrieve 10 more? (y/n)")
                    retrieveMore = retrieveMore.strip()
                    if retrieveMore == "y" or retrieveMore == "Y":
                        start = start + int(pagesize)
                    else:
                        j.close()
                        print "Last Command: " + displayQuery
                        break
                    j.close()
            else:
                print
                print "Setup a Server URL and an API Token"
        else:
            print
            print "[*] Usage [*]"
            print searchType + " help - Will display fields to search against"
            print searchType + " history - Show the history of the queries executed for " + searchType + "."
            print searchType + " query <input> - Search using a query for <input>"
            print
    else:
        print
        print "[*] Usage [*]"
        print searchType + " help - Will display fields to search against"
        print searchType + " history - Show the history of the queries executed on Alerts."
        print searchType + " query <input> - Search the Alerts for <input>"
        print
    return


class cbInteractive(cmd.Cmd):

    def __init__(self):
        global historyAll
        checkDirectories()
        # Load History from historyAll.log
        f = open('history/historyAll.log', 'r')
        for line in f:
            historyAll.append(line.strip())
        f.close()
        print "Starting cbInteract"
        print
        print "This was built to utilize the cbAPI to run Process, Binary and Alert searches."
        print "CbInteract also creates a daily journal file of the results of the searches and"
        print "retains the last 100 searches you have executed.  It also retains the history of"
        print "each type of search as the application is running."
        print
        print "show - show settings and history"
        print "set - set the Cb Server URL and/or the API Token"
        print
        print "alertSearch or aS - Allows you to search alerts"
        print "processSearch or pS - Allows you to run process searches"
        print "binarySearch or bS - Allows you to run binary searches"
        print "processEvents - Allows you to find additional regmod, filemod, etc. for results from processSearch"
        print
        cmd.Cmd.__init__(self)
        time.sleep(2)
        self.prompt = "#> "

    def do_processSearch(self, command):
        searchCb("processSearch", command)
        return

    def do_pS(self, command):
        searchCb("processSearch", command)
        return

    def do_alertSearch(self, command):
        searchCb("alertSearch", command)
        return

    def do_aS(self, command):
        searchCb("alertSearch", command)
        return

    def do_binarySearch(self, command):
        searchCb("binarySearch", command)
        return

    def do_bS(self, command):
        searchCb("binarySearch", command)
        return

    def do_processEvents(self, command):
        global cbC, historyAll, journalFile, SERVERURL, APITOKEN, historyProcessEvents
        if command == "help":
            print
            print "To gather the additional events from a process like regmod, filemod, etc."
            print "processEvents id:00000005-0000-1844-01d1-aa39d8d647ca segment_id:1"
            print
            print "Suggestion: You can get the id and segment_id from a processSearch"
            print "after the processSearch you can also use the proceeding number of the"
            print "search results to find this information by running:"
            print "processEvents run <number>"
            print
            print "processEvents show history - Shows a history of processes that have been searched."
            print
        elif command.count(" ") >= 1:
            c = command.split(" ")
            if ("id:" in c[0] and "segment_id:" in c[1]) or (c[0] == "run"):
                if (SERVERURL != None and APITOKEN != None):
                    connectServer()
                    print
                    try:
                        if (c[0] == "run"):
                            # Finish this...
                            pEventsID = int(c[1]) - 1
                            strEvents = historyProcessEvents[pEventsID].split("|")
                            cID = strEvents[1]
                            sID = strEvents[2]
                            #print cID + " " + sID
                        else:
                            cID = c[0]
                            cID = str(cID[3:])
                            sID = c[1]
                            sID = str(sID[11:])
                        #print cID + " " + sID
                        results = cbC.process_events(id=cID, segment=sID)
                    except:
                        print "Error with the results of the folowing query: " + command
                    searchString = "processEvents " + command + "\n"
                    historyAll.append(searchString)
                    journal = open(journalFile, 'a')
                    journal.write("\n\n")
                    journal.write("Process Extended Events Search\n")
                    journal.write(searchString)
                    #pprint.pprint(results['process']['childproc_complete'])
                    if "childproc_complete" in results['process']:
                        if len(results['process']['childproc_complete']) > 0:
                            print "Unique Child Processes"
                            journal.write("Unique Child Processes\n")
                            childProcesses = []
                            uniqueChildProcesses = []
                            for items in results['process']['childproc_complete']:
                                item = items.split("|")
                                #item[0] is time of execution
                                #item[1] is id
                                #item[2] is md5
                                #item[3] is path
                                #item[4] is pid
                                #item[5] (not sure)
                                strChildProcess = item[2] + "|" + item[3]
                                childProcesses.append(strChildProcess)
                            for i in childProcesses:
                                if i not in uniqueChildProcesses:
                                    uniqueChildProcesses.append(i)
                            for j in uniqueChildProcesses:
                                j = j.split("|")
                                print "Path: " + j[1] + " MD5: " + j[0]
                                journal.write("Path: " + j[1] + " MD5: " + j[0] + "\n")
                    if "crossproc_complete" in results['process']:
                        print
                        print "Cross Processes Executed"
                        journal.write("\nCross Processes Executed\n")
                        crossProcesses = []
                        uniqueCrossProcesses = []
                        for items in results['process']['crossproc_complete']:
                            item = items.split("|")
                            # item[0] is Description/Action
                            # item[1] is time of execution
                            # item[2] is id
                            # item[3] is md5
                            # item[4] is path
                            # item[5] (not sure)
                            # item[6] (not sure)
                            # item[7] (not sure)
                            strCrossProcess = item[0] + "|" + item[3] + "|" + item[4]
                            crossProcesses.append(strCrossProcess)
                        for i in crossProcesses:
                            if i not in uniqueCrossProcesses:
                                uniqueCrossProcesses.append(i)
                        for j in uniqueCrossProcesses:
                            j = j.split("|")
                            print "Action: " + j[0] + "Path: " + j[2] + " MD5: " + j[1]
                            journal.write("Action: " + j[0] + "Path: " + j[2] + " MD5: " + j[1] + "\n")
                    if "filemod_complete" in results['process']:
                        print
                        print "File Modifications (Summary)"
                        journal.write("\nFile Modifications (Summary)\n")
                        fileMod = []
                        uniqueFileMod = []
                        for items in results['process']['filemod_complete']:
                            item = items.split("|")
                            # item[0] is Description/Action
                            # item[1] is time of execution
                            # item[2] is path
                            # item[3] (not sure)
                            # item[4] (not sure)
                            # item[5] (not sure)
                            strFileMod = item[2]
                            fileMod.append(strFileMod)
                        for i in fileMod:
                            if i not in uniqueFileMod:
                                uniqueFileMod.append(i)
                        for j in uniqueFileMod:
                            j = j.split("|")
                            print "Path: " + j[0]
                            journal.write("Path: " + j[0] + "\n")
                    if "netconn_complete" in results['process']:
                        print
                        print "Network Connections (Summary)"
                        journal.write("\nNetwork Connections (Summary)\n")
                        netConn = []
                        uniqueNetConn = []
                        for items in results['process']['netconn_complete']:
                            item = items.split("|")
                            # item[0] is time of execution
                            # item[1] (not sure)
                            # item[2] port
                            # item[3] (not sure)
                            # item[4] URL
                            # item[5] Successful
                            strNetConn = item[4] + "|" + item[2] + "|" + item[5]
                            netConn.append(strNetConn)
                        for i in netConn:
                            if i not in uniqueNetConn:
                                uniqueNetConn.append(i)
                        for j in uniqueNetConn:
                            j = j.split("|")
                            print "URL: {:45} Port: {:5} Successful: {:5}".format(j[0], j[1], j[2])
                            netString = "URL: {:45} Port: {:5} Successful: {:5}\n".format(j[0], j[1], j[2])
                            journal.write(netString)
                    if "modload_complete" in results['process']:
                        print
                        print "DLL or other files loaded (Summary)"
                        journal.write("\nDLL or other files loaded (Summary)\n")
                        modLoad = []
                        uniqueModLoad = []
                        for items in results['process']['modload_complete']:
                            item = items.split("|")
                            # item[0] is time of execution
                            # item[1] md5
                            # item[2] path
                            strModLoad = item[1] + "|" + item[2]
                            modLoad.append(strModLoad)
                        for i in modLoad:
                            if i not in uniqueModLoad:
                                uniqueModLoad.append(i)
                        for j in uniqueModLoad:
                            j = j.split("|")
                            print "Path: " + j[1] + " MD5: " + j[0]
                            journal.write("Path: " + j[1] + " MD5: " + j[0] + "\n")
                    if "regmod_complete" in results['process']:
                        print
                        print "Registry Read/Changes (Summary)"
                        journal.write("\nRegistry Read/Changes (Summary)\n")
                        regMod = []
                        uniqueRegMod = []
                        for items in results['process']['regmod_complete']:
                            item = items.split("|")
                            # item[0] Action
                            # item[1] is time of execution
                            # item[2] Registry Path / Key
                            # item[3] (not sure)
                            strRegMod = item[0] + "|" + item[2]
                            regMod.append(strRegMod)
                        for i in regMod:
                            if i not in uniqueRegMod:
                                uniqueRegMod.append(i)
                        for j in uniqueRegMod:
                            j = j.split("|")
                            print "RegKey: " + j[1] + " Action Code: " + j[0]
                            journal.write("RegKey: " + j[1] + " Action Code: " + j[0] + "\n")
                    journal.close()
                    if "\n" in searchString:
                        print "Last Command: " + searchString[:-2]
                    else:
                        print "Last Command: " + searchString
                    print
                else:
                    print "The Server URL and/or the API Token is Misconfigured."
            elif (c[1] == "history"):
                for item in historyProcessEvents:
                    items = item.split("|")
                    print str(items[0]) + "|" + str(items[3]) + "|" + str(items[4]) + "|" + str(items[1]) + "|" + str(items[2])
                print "ID, Hostname, Process Name, Unique Process ID, Segment ID"
            else:
                print
                print "To gather the additional events from a process like regmod, filemod, etc."
                print "processEvents id:00000005-0000-1844-01d1-aa39d8d647ca segment_id:1"
                print
                print "Suggestion: You can get the id and segment_id from a processSearch"
                print "after the processSearch you can also use the proceeding number of the"
                print "search results to find this information by running:"
                print "processEvents run <number>"
                print
                print "processEvents show history - Shows a history of processes that have been searched."
                print
        else:
            print
            print "To gather the additional events from a process like regmod, filemod, etc."
            print "processEvents id:00000005-0000-1844-01d1-aa39d8d647ca segment_id:1"
            print
            print "Suggestion: You can get the id and segment_id from a processSearch"
            print "after the processSearch you can also use the proceeding number of the"
            print "search results to find this information by running:"
            print "processEvents run <number>"
            print
            print "processEvents show history - Shows a history of processes that have been searched."
            print
        return


    def do_set(self, command):
        global SERVERURL, APITOKEN
        if command.count(" ") == 1:
            command = command.split(" ")
            if command[0] == "serverURL":
                SERVERURL = command[1]
            elif command[0] == "apiToken":
                APITOKEN = command[1]
        else:
            print "[*] Usage [*]"
            print "set serverURL http://127.0.0.1"
            print "set apiToken 45454545454545454545af"
            print
        return

    def do_show(self, command):
        global SERVERURL, APITOKEN
        if (command == "all"):
            print "Server URL: " + str(SERVERURL)
            print "API Token: " + str(APITOKEN)
        elif (command == "serverURL"):
            print "Server URL: " + str(SERVERURL)
        elif (command == "apiToken"):
            print "API Token: " + str(APITOKEN)
        elif (command == "history"):
            count = 1
            for i in historyAll:
                print str(count) + ": " + i
                count += 1
        else:
            print "show all - Show all of the settings configured."
            print "show serverURL - Show the set Server URL"
            print "show apiToken - Show the set API Token"
            print "show history - Show the history of searches executed"
        return

    def emptyline(self):
        pass

    def do_exit(self, line):
        global historyAll
        # Save the last 100 commands in the history
        f = open('history/historyAll.log', 'w')
        if len(historyAll) > 100:
            for i in range((len(historyAll)-100),len(historyAll)):
                saveLine = historyAll[i] + '\n'
                f.write(saveLine)
        else:
            for i in range(0,len(historyAll)):
                saveLine = historyAll[i] + '\n'
                f.write(saveLine)
        f.close()
        return True

    def postloop(self):
        print

if __name__ == '__main__':
    rt = cbInteractive()
    t1 = Thread(target = rt.cmdloop)
    t1.start()
    t1.join()















