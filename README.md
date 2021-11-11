# CVE_2012-2982
This script was written for the 'Intro PoC Scripting' room on TryHackMe.com as a conversion from the Metasploit module.

# CREDITS

I did not discover this vulnerability. I was also unable to figure out who discovered it. If you're reading this and you know who did, Please reach out to me at slizbinksman@gmail.com so i can update this and give credit where its due.

CVE:  
https://nvd.nist.gov/vuln/detail/CVE-2012-2982  
https://www.kb.cert.org/vuls/id/788478  

Metasploit:  
https://www.rapid7.com/db/modules/exploit/unix/webapp/webmin_show_cgi_exec/
https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/webmin_show_cgi_exec.rb  

MSF Author:  
juan vazquez <juan.vazquez@metasploit.com>

# Vulnerability

The `show.cgi` file in the `file` directory contains an input validation flaw that allows elevated remote code execution from an authenticated user. To exploit the vulnerability, you have to pipe a random alpha numeric string into the payload via the URL `/file/show.cgi/bin/`.
