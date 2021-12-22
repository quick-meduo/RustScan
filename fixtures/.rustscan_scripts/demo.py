#!/usr/bin/python3
#tags = ["core_approved", "example",]
#developers = [ "example", "https://example.org" ]
#call_format = "python3 {{script}} {{ip}} {{port}}"

# Scriptfile parser stops at the first blank line with parsing.
# This script will run itself as an argument with the system installed python interpreter, only scanning port 80.
# Unused filed: ports_separator = ","

trigger_port = "80"

import sys
import mysql.connector
import threading
import signal
import time
import trace
import os

print('Python script ran with arguments', str(sys.argv[1]))
ip = str(sys.argv[1])
ports = str(sys.argv[2]).split(",")


class thread_with_trace(threading.Thread):
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False
 
  def start(self):
    self.__run_backup = self.run
    self.run = self.__run     
    threading.Thread.start(self)
 
  def __run(self):
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup
 
  def globaltrace(self, frame, event, arg):
    if event == 'call':
      return self.localtrace
    else:
      return None
 
  def localtrace(self, frame, event, arg):
    if self.killed:
      if event == 'line':
        raise SystemExit()
    return self.localtrace
 
  def kill(self):
    self.killed = True


def handler(signal_received, frame):
    print('detected ',signal_received)
    sys.exit(0)

def send_signal(sig):
    os.kill(os.getpid(), sig)

def scanning(ip,port):
    try:
        conn = mysql.connector.connect(
            host=ip,
            port=port,
            user="root",
            password="sinux123",
            connection_timeout=1
            )
        print("found mysql on ",ip,port)
    except mysql.connector.errors.ProgrammingError as e:
        if "denied" in str(e):
            print("found mysql on ",ip,port)
    except mysql.connector.errors.OperationalError as e:
        if "timed" in str(e):
            print("timed out on ",ip,port)
    except:
        print("Something else went wrong")

if __name__ == '__main__':
    # signal.signal(signal.SIGUSR1, handler)
    threads = []
    for port in ports:
        t = thread_with_trace(target = scanning,args=(ip,port))
        t.start()
        threads.append(t)
   
    time.sleep(1)
    for thr in threads:
        thr.kill()
        thr.join()