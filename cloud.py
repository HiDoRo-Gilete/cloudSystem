import os,codecs
import Converter,DES
import datetime


Directory = './Cloud'

class Cloud:
    def __init__(self):
        if not os.path.exists(Directory):
            os.makedirs(Directory)
        self.secfiles = os.listdir(Directory)
        self.secconfigs=[]
        self.xorValue = b'\x4E\x48\x4F\x4D\x41\x54\x50\x48'
        self.getSec()
        self.allFiles = self.list_file()
    def getSec(self):
        if len(self.secfiles) ==0:
            for i in range(0,8):
                self.secconfigs.append('config_'+str(i)+'.sec')
                f=open(Directory+'/'+self.secconfigs[i],'w+b')
                if i == 0:
                    f.write(b'\x00\x00'+self.xorValue+b'\x00'*4086)
                else:
                    f.write(b'\x00'*4096) 
                f.close()
            return
        for i in range(0,8):
            self.secconfigs.append('config_'+str(i)+'.sec')
        if 'config_0.sec' not in self.secfiles:
            raise ValueError('Cannot understand the system')
        else:
            for i in range(1,8):
                if self.secconfigs[i] not in self.secfiles:
                    f=open(Directory+'/'+self.secconfigs[i],'wb')
                    f.write(b'\x00'*4096)
                    f.close()
    def list_file(self):
        filenames=[]
        for secconfig in self.secconfigs:
            f= open(Directory+'/'+secconfig,'rb')
            if secconfig == 'config_0.sec':
                #skip first 32 bytes in config_0.sec
                f.read(32)
            entry = f.read(32)
            while entry !=b'':
                if entry[0]!=0 and entry[0] !=15:
                    #print(entry)
                    filename = Converter.xorMes(entry[1:12],self.xorValue).decode()
                    filename = filename.replace('$','')
                    extend = entry[12:17].decode().replace('$','')
                    hiden = Converter.decimalToBit(entry[17],1)[6]
                    pw = Converter.decimalToBit(entry[17],1)[7]
                    bytedate = Converter.decimalToBit(entry[26],1)+Converter.decimalToBit(entry[27],1)
                    y = Converter.bitstring_to_bytes(bytedate[0:7],1)[0]
                    m= Converter.bitstring_to_bytes(bytedate[7:11],1)[0]
                    d = Converter.bitstring_to_bytes(bytedate[11:16],1)[0]
                    bytetime = Converter.decimalToBit(entry[28],1)+Converter.decimalToBit(entry[29],1)
                    h = Converter.bitstring_to_bytes(bytetime[0:5],1)[0]
                    mi= Converter.bitstring_to_bytes(bytetime[5:11],1)[0]
                    s = Converter.bitstring_to_bytes(bytetime[11:16],1)[0]
                    secsize = entry[30] *256 +entry[31]
                    filesize = 4096*(secsize-1)
                    lastFile = open(self.accessSecFile(filename+'.'+extend,secsize-1),'rb')
                    data = lastFile.read(1)
                    while data !=b'\x00': filesize,data=filesize+1,lastFile.read(1)
                    filenames.append({'name':filename.replace("$","")+'.'+extend,
                                      'date':str(d)+'/'+str(m)+'/'+str(y),
                                      'time':str(h)+':'+str(mi)+':'+str(s),
                                      'size':filesize,
                                      'hidden':hiden,
                                      'password': pw
                                      })
                    
                entry=f.read(32)
        return filenames
    
    def addFile(self,pathFile,mode,password = None):
        #print(pathFile,mode,password)
        config0 = open(Directory+'/config_0.sec','rb')
        entry0 = config0.read(32)
        if int(entry0[1])+int(entry0[0])*256 < 999:
            filesource = ""
            try:
                filesource = open(pathFile,'rb')
            except Exception as e:
                #print(e)
                raise ValueError('Path file is invalid!')
            filename = pathFile.split('/')
            filename = filename[len(filename)-1]
            pos,idFile = self.findAvalible()
            #print(pos,idFile)
            filesize = os.path.getsize(pathFile)
            if  filesize>1024*1024*1024:
                raise ValueError('File is too large! > 1GB')
            temp = filename
            if filename.find('.'): temp=filename[:filename.find('.')]
            if len(temp) >11: 
                raise ValueError('File name cannot exceed 11 characters!')
            elif len(filename)-len(temp)>6:
                raise ValueError('Cannot support this file!')
            elif filename in [file['name'] for file in self.allFiles]:
                raise ValueError('Filename is exists in cloud! Please rename and try again!')
            for config in self.secconfigs:
                if config in filename: 
                    raise ValueError('Filename is not allow!')
            if password !=None and len(password) !=8:
                raise ValueError('password must be 8 character!')
            data=filesource.read(4096)
            secsize=0
            while data!=b"":
                f = open(Directory+'/'+self.getMapFilename(filename+'_'+str(secsize)+'.sec'),'wb')
                if len(data) != 4096: data+=b'\x00'*(4096-len(data))
                f.write(data)
                secsize+=1
                data=filesource.read(4096)
                f.close()
            filedes = open(Directory+'/'+self.secconfigs[idFile],'r+b')
            allentry = filedes.read()
            entry = self.getEntry(filename,secsize,mode,password)
            allentry = allentry[0:32*pos]+entry+allentry[32*pos+32:]
            filedes.seek(0)
            filedes.write(allentry)
            filesource.close()
            filedes.close()
            f=open(Directory+'/'+self.secconfigs[0],'r+b')
            data = f.read()
            numfile = int(data[0])*256 + int(data[1]) + 1
            bnumfile = Converter.intToByte(numfile,2)
            f.seek(0)
            f.write(bnumfile + data[2:])
            #print(bnumfile+data[2:])
            f.close()
            self.allFiles=self.list_file()
        else:
            raise ValueError('There are 999 files in cloud and cannot add another file!')
    def findAvalible(self):
        idFile = 7
        while idFile>=0:
            f = open(Directory+'/'+self.secconfigs[idFile],'rb')
            allentry = f.read()
            if idFile == 7 and allentry[4064] == 255:
                return self.findDeleteFile()
            elif idFile != 0 and allentry[0] == 0:
                idFile -=1 
            else:
                pos = 0
                if idFile == 0: pos = 1
                while pos < 128:
                    if allentry[pos*32] == 0:
                        return pos,idFile
                    pos+=1
                    if pos ==128: 
                        return 0,idFile+1
            f.close()
    def exportFile(self,filename,filenamedes,path):
        pos = [file['name'] for file in self.allFiles].index(filename)
        if pos <0:
            raise ValueError('Filename is not exists in cloud! Please check and try again!')
        #idFile,index = pos//128,pos%128
        secsize = self.allFiles[pos]['size']//4096 + min(1,self.allFiles[pos]['size']%4096)
        with open(path+'/'+filenamedes,'wb+') as filedes:
            #print(secsize)
            for i in range(secsize):
                filesrc = open(self.accessSecFile(filename,i),'rb')
                data = filesrc.read()
                data =data[:data.find(0)]
                filedes.write(data)
                filesrc.close()
            filedes.close()
    def deleteFile(self,filename):
        try:
            pos = [file['name'] for file in self.allFiles].index(filename)
        except Exception as e:
           #print(e)
            raise ValueError('Filename '+filename+' is not exists in cloud! Please check and try again!')
        idFile,index = pos//128,pos%128+1
        f = open(Directory+'/'+self.secconfigs[idFile],'r+b')
        allentry = f.read()
        newall = allentry[:32*index]+b'\x0F'+ allentry[32*index+1:]
        f.seek(0)
        #print(newall)
        f.write(newall)
        f.close()
        self.allFiles.pop(pos)
    def recoverFile(self):
        number = 0
        for config in self.secconfigs:
            f = open(Directory+'/'+config,'r+b')
            allentry = f.read()
            index =0
            if config == 'config_0.sec': index =1
            while index<128:
                entry =allentry[index*32:index*32+32]
                if entry[0] == 15: 
                    ffile = Converter.xorMes(allentry[index*32+1:index*32+12],self.xorValue).decode().replace('$','')
                    lfile = allentry[index*32+12:index*32+17].decode().replace('$','')
                    filename=ffile +'.'+lfile
                    i = 0
                    while filename in [file['name'] for file in self.allFiles]:
                        ffile = ffile[:min(len(ffile),11-len(str(i)))] +str(i)
                        filename = ffile+'.'+lfile
                    ffile = (ffile+ '$'*(11-len(ffile))).encode()
                    ffile = Converter.xorMes(ffile,self.xorValue)
                    allentry = allentry[:index*32]+b'\xFF'+ffile+allentry[index*32+12:]
                    number = 1
                index+=1
            f.seek(0)
            f.write(allentry)
            f.close()
        self.allFiles = self.list_file()
        return number
    def findDeleteFile(self):
        pass
    def getEntry(self,filename,secsize,mode,password=None):
        lfilename,extend = filename.encode(),'\x00\x00\x00\x00\x00'
        if filename.find('.'): 
            lfilename = filename[0:filename.find('.')].encode()
            if lfilename!= 11: lfilename+=b'$' *(11-len(lfilename))
            extend = (filename[filename.find('.')+1:]).encode()
            if len(extend) !=5: extend+=b'$'*(5-len(extend))
        bfilename = Converter.xorMes(lfilename,self.xorValue)
        entry =b'\xFF'
        statustring = '00000'
        pw=b'\x00'*8
        if secsize <=25600: 
            self.backupFile(filename)
            statustring +='1'
        else: statustring+='0'
        if mode == 1:   statustring+= '1'
        else: statustring +='0'
        if password != None:
            statustring+='1'
            cipher=DES.encrypt('password',password)
            pw = cipher.encode()
        else: statustring+='0'
        status=Converter.bitstring_to_bytes(statustring,1)
        size = Converter.intToByte(secsize,2)
        current_time = datetime.datetime.now()
        #ngay tao
        y,m,d= current_time.year-1980, current_time.month, current_time.day
        byear = Converter.decimalToBit(y,0) 
        if len(byear) !=7: byear = '0'*(7-len(byear)) +byear
        bmonth= Converter.decimalToBit(m,0) 
        if len(bmonth) !=4: bmonth = '0'*(4-len(bmonth)) +bmonth
        bdate = Converter.decimalToBit(d,0) 
        if len(bdate) !=5: bdate = '0'*(5-len(bdate)) +bdate
        Date= Converter.bitstring_to_bytes(byear+bmonth+bdate,2)
        #gio tao
        h,m,s= current_time.hour, current_time.minute, current_time.second//2
        bhour = Converter.decimalToBit(h,0)
        if len(bhour) !=5: bhour = '0'*(5-len(bhour)) +bhour
        bminute= Converter.decimalToBit(m,0) 
        if len(bminute) !=6: bminute = '0'*(6-len(bminute)) +bminute
        bsecond = Converter.decimalToBit(s,0) 
        if len(bsecond) !=5: bsecond = '0'*(5-len(bsecond)) +bsecond
        Time= Converter.bitstring_to_bytes(bhour+bminute+bsecond,2)
        #print(entry+bfilename+extend+status+pw+Date+Time+size)
        return entry+bfilename+extend+status+pw+Date+Time+size
    def getMapFilename(self,filename):
        return filename
    def backupFile(self,filename):
        pass
    def accessSecFile(self,filename,id):
        return Directory+'/'+self.getMapFilename(filename+'_'+str(id)+'.sec')



# cloud = Cloud()
# f = open(Directory+'/'+cloud.secconfigs[0],'rb')
# print(f.read(32))
# data = f.read(32)
# for i in range(len(data)):
#     print(data[i])
# print (cloud.allFiles)
# cloud.exportFile('seminar.pdf','test.pdf','.')
#cloud.addFile('D:/code python/2024/Blockchain/Lab 1/RAFT/README.md',1,)
#cloud.deleteFile('README.md')
# print(cloud.allFiles)
# number = cloud.recoverFile()
# print(number)
