#!/usr/bin/env python
#
# Copyright (c) 2021, Ameen Ali Shaikh <ameenalishaikh@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#    NAME
#      MemoryEye.py - Memory scanner script to search for clear-text secrets in process memory.
#
#    DESCRIPTION
#      Memory scanner script to search for clear-text secrets in run-time memory of a process.
#         Reads input from config/config.ini file.
#
#    NOTES
#      1. Recommended to run as root user as root has access to all the processes currently running
#      2. Generates output in .csv format
#      3. Currently supports only Linux based OS
#
#

import os
import sys
import glob
import re

class RootFolderDef:
    __rootfolder=None
    def __init__(self,aRoot='PRODUCT_ROOT'):
        self.setRootFolder(aRoot)
    def setRootFolder(self,aRoot):
        #if adeRoot in os.environ:
        #    self.__rootfolder=str(os.environ.get(aRoot))+"/test/src/passwd-scanner/"
        self.__rootfolder="/ameshaik/passwd-scanner/"
        return 0
    def get(self):
        return self.__rootfolder
    def check(self):
        if not os.path.isdir(self.__rootfolder):
            return False
        else:
            return True
class Conf:
    __dict={}
    def __init__(self,fname):
        self.fname=fname
        self.loadConf(fname)
    def loadConf(self,fname):
        if os.path.isfile(fname):
            f=open(fname,'r')
            all=[x.strip() for x in f if not x.strip().startswith('#') and x.strip().find('=')>1]
            f.close()
            for x in all:
                pos=x.find('=')
                self.__dict[x[:pos].strip()]=x[pos+1:].strip()
        if len(sys.argv)>0:
            all=[x.strip() for x in sys.argv[1:] if x.strip().find('=')>0]
            for x in all:
                pos=x.find('=')
                self.__dict[x[:pos].strip()]=x[pos+1:].strip()
        return 0
    def get(self,key):
        return self.__dict.get(key)
    def set(self,key,val):
        self.__dict[key]=val
    def eq(self,key,val):
        return self.__dict.get(key)==val
class TraceLog:
    __fp = None
    def __init__(self,fname):
        self.fname=fname
        self.__fp = open(fname,'w')
        self.trace("#"*100,False)
    def trace(self,s,b=True):
        if b:
            print s
        self.__fp.writelines(s+'\n')
        self.__fp.flush()
    def __del__(self):
        self.__fp.close()
class ProcLog:
    __fp = None
    def __init__(self,fname):
        self.fname=fname
        self.__fp = open(fname,'w')
        self.pidinfo("#"*100,False)
    def pidinfo(self,s,b=True):
        if b:
            print s
        self.__fp.writelines(s+'\n')
        self.__fp.flush()
    def __del__(self):
        self.__fp.close()
class MyException(Exception):
    pass

def readFile(filename):
    if not os.path.isfile(filename):
        return []
    f = open(filename,"r")
    ret=[x.strip() for x in f]
    f.close()
    return ret
def writeFile(all,filename):
    f = open(filename,"w")
    for x in all:
        f.write(x+'\n')
    f.close()
def getPipeValue(cmdline):
    log.trace(cmdline,debugFlag)
    pipe=os.popen(cmdline)
    all=[x for x in pipe]
    pipe.close()
    return all
def getOsType():
    import platform
    PLATFORM_UNAME=platform.uname()
    if PLATFORM_UNAME[0] == 'Linux':return 1
def initEnvCheck():
    mypid=os.getpid()
    log.trace('Debug:mypid='+str(mypid),debugFlag)
    osType=getOsType()
    conf.set('osType',osType)
    passwords=conf.get('passwords')
    if not passwords:
        raise MyException, 'Pls get param[passwords] in config.ini, eg: passwords=Test1234, oracle'
    if conf.get('pids') or conf.get('procNames'):
        if conf.get('pids'):
            tip='pids'
        else:
            tip='procNames'
        pids=str(conf.get(tip))
        pidlst=pids.split(',')
        if not pidlst:
            raise MyException, 'You have assigned invalid param %s[%s], pls check'%(tip,pids)
    else:
        log.trace('Info : Scanning all the running processes. Scan will take more time to complete.')
        pids=os.popen("""ps -ef|awk 'NR>1{print $2}'""")
        pidlst=pids.read().splitlines()
        if not pidlst:
            raise MyException, 'No active processes running. Exiting without scan.'
    procInfo=[]
    procDesc=[]
    for pid in pidlst:
        procInfo+=os.popen("""ps -ef |grep %s |grep -v grep |grep -v %s|awk '{print $8"_"$2}'|sed 's/\\/.*\\///'"""%(pid,__file__)).readlines()
        procDesc+=os.popen("""ps -eo pid,user,cmd,comm,args |grep %s |grep -v grep |grep -v %s"""%(pid,__file__)).readlines()
    procInfo=[x.strip() for x in procInfo if x[x.rfind('_')+1:].strip()!=mypid]
    log.trace('Debug:procInfo='+str(procInfo),debugFlag)
    for item in procDesc:
        pinfo.pidinfo(str(item),debugFlag)
    if not procInfo:
        raise MyException,'You have assign param %s[%s], but the process not exist, plz check'%(tip, pids)
    conf.set('procInfo',procInfo)
    log.trace('Info : initEnvCheck successful!')
def runScan():
    passwords=conf.get('passwords')
    passwords=passwords.split(',')
    log.trace('Debug:passwords='+str(passwords),debugFlag)
    procInfo=conf.get('procInfo')
    log.trace('Debug:procInfo='+str(procInfo),debugFlag)
    procInfo=[x.strip() for x in procInfo]
    pids=[x[x.rfind('_')+1:] for x in procInfo]
    log.trace('Debug:pids='+str(pids),debugFlag)
    osType=conf.get('osType')
    grepstr='grep -i'
    stringsCmd='strings'
    result=[]
    if osType==1:
        for x,y in zip(pids,procInfo):
            tmpfile=rootfolderpath+'results/tmpgdb.txt'
            writeFile(['generate-core-file %sresults/%s_core.txt'%(rootfolderpath,y),'q'],tmpfile)
            os.system('gdb -p %s < %s > /dev/null 2>&1'%(x,tmpfile))
            log.trace('Info :strings %s_core.txt'%(y))
            for p in passwords:
                cmdline='%s %sresults/%s_core.txt|%s "%s"'%(stringsCmd,rootfolderpath,y,grepstr,p)
                log.trace('Debug:ExecCmd:%s'%cmdline,debugFlag)
                tmps=os.popen(cmdline).readlines()
                tmps=[y.split('_')+[p]+[x.strip()] for x in tmps]
                result+=tmps
                for x in tmps:
                    log.trace(str(x).strip('[]').replace('\'',''))
            cmdline='rm -f %sresults/%s_core.txt'%(rootfolderpath,y)
            os.popen(cmdline)
        cmdline='rm -f %s'%(tmpfile)
        os.popen(cmdline)
    conf.set('result',result)
    log.trace('Info : runCheck successful!')
def writeResult():
    result=conf.get('result')
    result=[x[:3]+['','','']+[x[-1]] for x in result]
    result=[str(x).strip('[]').replace('\'','')+'\n' for x in result]
    f=open(rootfolderpath+'results/result.csv','w')
    f.writelines('Process Name,PID,Suspected Password Text,Whether an Issue (yes/no)?,Verified by (Emp ID),Verification Comments,Details\n')
    for x in result:
        f.writelines(x)
    f.close()
def main():
    initEnvCheck()
    runScan()
    writeResult()

global log,conf,debugFlag,rootfolder
rootfolder = RootFolderDef()
if not rootfolder.check():
    raise MyException,'Could not find the Password Scanner script. Pls check whether PRODUCT_ROOT/test/src/passwd-scanner/ location exists.'
rootfolderpath=rootfolder.get()
log = TraceLog(rootfolderpath+'results/trace.log')
pinfo = ProcLog(rootfolderpath+'results/procInfo.log')
conf = Conf(rootfolderpath+'config/config.ini')
debugFlag=conf.get('debugFlag')=='True'

if __name__ == '__main__':
    main()
