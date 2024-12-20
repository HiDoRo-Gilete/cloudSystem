import cloud,time
from threading import Thread
def menu():
    print('0. Exit')
    print('1. List all file')
    print('2. Import file')
    print('3. Export file')
    print('4. Delete file')
    print('5. Recover file')
def getstring(str):
    vailible = 24-len(str)
    capacityright = vailible//2
    right = " "*capacityright
    left = " " * (vailible-capacityright)
    return left+str+right 
class Main:
    def __init__(self):
        self.cl= None
        self.getData = False
    def initializeCloud(self):
        self.cl = cloud.Cloud()
    def main(self):
        thread = Thread(target=self.initializeCloud,args=())
        thread.start()
        print("System is starting")
        while thread.is_alive():
            print('.')
            time.sleep(0.5)
            print('.')
            time.sleep(0.5)
            print('.')

        number = -1
        self.result = None
        while number!=0:
            menu()
            number = int(input("Your select: "))
            thr = None
            if number != 0:
                print('Wait for process')
            if number == 1:
                thr = Thread(target=self.listAllFile,args=())
                thr.start()
            elif number == 2:
                thr = Thread(target=self.importFile,args=())
                thr.start()
            elif number ==3:
                thr = Thread(target=self.exportFile,args=())
                thr.start()
            elif number == 4:
                thr = Thread(target=self.deleteFile,args=())
                thr.start() 
            elif number == 5:
                thr = Thread(target=self.recoverFile,args=())
                thr.start() 
            
            while thr != None and thr.is_alive():
                if self.getData:
                    print('.')
                    time.sleep(0.5)
                    print('.')
                    time.sleep(0.5)
                    print('.')
                else: time.sleep(0.2)
            if number!=0:
                print(self.result)
            self.getData = False
    def listAllFile(self):
        try:
            self.getData = True
            self.result = '|'
            self.result += getstring('Name')+'|'+getstring('Date')+'|'+getstring('Time')+'|'+getstring('Size')+'|'+getstring('Password')+'|\n'
            for file in self.cl.allFiles:
                if file['hidden']=='0':
                    self.result+='|'+getstring(file['name'])+'|'+getstring(file['date'])+'|'
                    self.result+=getstring(file['time'])+'|'+getstring(str(file['size']))+'|'
                    if file['password'] == '1': self.result+=getstring('Yes')
                    else: self.result+=getstring('No')
                    self.result +='|\n'
        except Exception as e:
            self.result = e
        finally: 
            time.sleep(0.1)
    def importFile(self):
        try:
            self.result = ""
            path = input("Please input path file: ")
            try:
                f = open(path)
                f.close()
            except:
                print("Path file is invalid!")
                return
            mode=int(input("Plase input hidden mode (1: hidden, 0: no hidden): "))
            if mode != 0 and mode != 1:
                print("Mode value must be 0 or 1!")
                return
            password=input("Please Input password for this File (must be 8 character). Enter to skip password: ")
            if len(password) !=0 and len(password) != 8:
                print('Invalid Password!')
                return
            self.getData = True
            time.sleep(0.5)
            if len(password) == 0: self.cl.addFile(path,mode)
            else: self.cl.addFile(path,mode,password)
            filename = path.split('/')[len(path.split('/'))-1]
            self.result="Create file "+filename+" success!"
        except Exception as e:
            self.result = e
    def exportFile(self):
        try:
            self.result = ""
            filesrc = input("Please input filename to Export: ")
            filedes=input("Create filename for export: ")
            folder =input("Please input path folder to contain file destination: ")
            self.getData = True
            time.sleep(0.5)
            self.cl.exportFile(filesrc,filedes,folder)
            self.result="Create file "+filedes+" into path "+folder+"/"
        except Exception as e:
            self.result = e
    def deleteFile(self):
        try:
            self.result = ""
            file= input("Please input filename Delete: ")
            self.getData = True
            time.sleep(0.5)
            self.cl.deleteFile(file)
            self.result="Delete file "+file+" success!"
        except Exception as e:
            self.result = e
    def recoverFile(self):
        try:
            self.result = ''
            self.getData = True
            number =self.cl.recoverFile()
            self.result = "Find and recovery "+str(number)+" files"
        except Exception as e:
            self.result = e
        
main = Main()
main.main()