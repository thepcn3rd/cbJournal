# cbJournal
Carbon Black API client app to create a journal of searches and results of those searches.

I found that after I had done research on the web interface for an investigation I needed to save the relevant information into a text file for retention.  I built this simple python client to interface with the CbAPI.  The purpose is during an investigation if I find a relevant search related to an investigation the search can be run in this client and the results can be saved to a text file.  I can then copy that information from alert, binary or process searches that are conducted into other software for retention of the details of an investigation.
 
I used Python 2.7.x with the Cmd library.
 
How to use
---------------
1. Before you launch the client or after you initially launch the client you need to setup the Carbon Black Servers URL and the API Token it will be using.
1a. Modify the cbAIO.py file and change the Server URL and API Token
1b. After launching the client you will need to set the Server URL or API Token by running:
     - set serverURL http://127.0.0.1
     - set apiToken 4454545454545454
2. After you setup the Server URL and/or API Token then you can search for Alerts, Processes, and Binaries:
2a. alertSearch is the same as if you were search to Triage Alerts
     - alertSearch - Provides detail about how to conduct Alert Searches
     - aS - Is the abbreviated way of using alertSearch
     - alertSearch help - Displays some of the ways that you can utilize the alertSearch as if you were searching in the web GUI
     - alertSearch query or aS q - Is the foundation of beginning to query the Alerts
     - alertSearch query process_name:putty.exe alert_severity:[40 TO *] - An example of a search that can be executed
     - alertSearch history - Will show you the history of the alertSearch queries you have conducted
     - show history - Will show you the last 100 searches you have conducted in the client
2b. processSearch - Provides detail about how to conduct Process Searches
     - pS - Is abbreviated way of using alertSearch
     - Other commands are similar to the above description of how to use alertSearch
2c. binarySearch - Provides detail on how to conduct Binary Searches
     - bS - Is the abbreviated way of using binarySearch
     - Other commands are similar to the above description in the alert search section
3. processEvents - Provides detail of filemods, regmods, etc. for a given process.  There are 2 ways to utilize this:
3a. processEvents id:<process unique id> segment_id:<> - Both the id and the segment id need to be placed in the processEvents.  The segment_id is important to pull the correct time-frame of information.
3b. The other way to utilize it is by running a processSearch first.  After a successful processSearch you will get the results that correspond with a preceding number incrementing starting with 1.  You can then use that ID of the search by running:
     - processEvents run 1 - This will pull back additional detail about the first search result from a process search.
 
Feel free to customize the application for your needs.  I use this client to complement the results that I need to retain as I find them in the provided web GUI.
 
Fixed the bug of needing to create the history/historyAll.log when the application is first executed before opening it.
 
I created this in Python 2.7.x.

Leon Trappett (thepcn3rd)
