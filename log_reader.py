import os
import sys
import subprocess
import threading
from collections import defaultdict
from queue import Queue
import time
import re

class LogReader:
    PATTERN = re.compile(r'\d+[.]\d+[.]\d+[.]\d+')
    
    def __init__(self, cluster, datadict):
        self.__datadict = datadict
        self.__cluster = cluster
        
    def __findSSH(self):
      if self.__cluster['sshd']:
          print('Начало процесса поиска')
          for log_line in self.__cluster['sshd']:
              if log_line:
                ip_addr = re.findall(LogReader.PATTERN, log_line)
                if ip_addr:
                    self.__perInfo = self.__GetPersonInfo(ip_addr[0])               
                    if 'Disconnected' in log_line:
                        print('Соединение завершено, адрес:', ip_addr[0])
                    elif 'Accepted' in log_line:
                        print('Соединения обнаружено, адрес:', ip_addr[0])
                        self.__datadict[ip_addr[0]].append(self.__perInfo.getRegData())
          self.__cluster['sshd'].remove(log_line)
              
      elif self.__cluster['sudo']:
                  for ips in self.__datadict:
                    for command_line in self.__cluster['sudo']:
                        try:
                            if self.__datadict[ips][0][0] in command_line:
                                self.__datadict[ips].append(self.__GetPersonInfo(None).getCommandData(command_line))
                                print(self.__datadict)
                        except:
                            pass
                        self.__cluster['sudo'].remove(command_line)
                        #print(self.__datadict)
                           
    def starting_check(self):
        if not os.getuid():
            self.__findSSH()
        else:
            print('Запустите скрипт от имени root!')
            sys.exit(1)
            
    class __GetPersonInfo:
        PTS_PATTERN = re.compile(r'pts\S+\s{0}')
        USER_PATTERN = re.compile(r'\S+\s{0}')
        COMMAND_PATTERN = re.compile(r'COMMAND=.+')
        
        def __init__(self, ip):
            self.__ip = ip
        
        def getRegData(self):
            p = subprocess.Popen('who', shell=True, stdout=subprocess.PIPE)
            for line in p.stdout:
                line = line.decode()
                if self.__ip in line:
                    pts = re.search(self.PTS_PATTERN, line).group()
                    user = re.search(self.USER_PATTERN, line).group()
                    if pts:
                        return (pts, user)

        def getCommandData(self, line):
            try:
                if not self.__ip:
                    return re.search(self.COMMAND_PATTERN, line).group()
            except:
                return 1
            
class DataClassifier:
    NAME_PATTERN = re.compile(r'(\s{0}\S+)\[')
    PROC_PATTERN = re.compile(r']?:\s(.+)')
    
    def __init__(self, num_threads):
        self.__LogReaderDict = defaultdict(list)
        self.__logdict = defaultdict(list)
        self.__main_queue = Queue()
        self.__numth = num_threads
        try:
            #self.__logs = subprocess.Popen('sudo journalctl --since=2021-01-01', shell=True, stdout=subprocess.PIPE)
            self.__logs = subprocess.Popen('sudo journalctl -f --since=' + time.strftime('%H:%M:%S'), shell=True, stdout=subprocess.PIPE)
        except:
            print('Не удалось подключиться к потоку логирования')
            sys.exit(1) 

    def __make_process(self):
        for num in range(self.__numth):
            thread = threading.Thread(target=(self.__create_cluster))
            thread.setDaemon(True)
            thread.start()
        
        for line in self.__logs.stdout:
            self.__main_queue.put(line.decode())
        
        self.__main_queue.join()
       
    def run(self):
        if self.__numth and not os.getuid():
            self.__make_process()
        else:
            print('Запустите скрипт от имени root!')
            sys.exit(1)
    
    def __create_cluster(self):
        while True:
            log_line = self.__main_queue.get()
            data_proc = 'Starting message'
            self.__main_queue.task_done()
            
            try:
                data_proc = re.findall(self.PROC_PATTERN, log_line)[0]
                name_proc = re.findall(self.NAME_PATTERN, log_line)[0]         
            except:
                name_proc = 'kernel'
                
            self.__logdict[name_proc].append(data_proc)
            
            reader = LogReader(self.__logdict, self.__LogReaderDict)
            reader.starting_check()            
            
now = time.time()
t = DataClassifier(1)
t.run()
print('Время выполнения:', time.time() - now)

































        
    
        