import requests
from pywin32 import win32evtlog
import json

server = 'localhost'  # name of the target computer to get event logs
logtype = ['System', 'Application', 'Security']


while True:
    for log_t in logtype:
        hand = win32evtlog.OpenEventLog(server, log_t)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                json_data = {"Event Category": event.EventCategory, "TimeStamp": (event.TimeGenerated,),
                             "Event Source Name": (event.SourceName,), "Event ID": (event.EventID,),
                             "Event Type": event.EventType}
                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
                data = event.StringInserts
                if data:
                    for msg in data:
                        r_post = requests.post("http://127.0.0.1:14774", data=json_data, headers=headers)
