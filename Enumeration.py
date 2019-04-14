#!/usr/bin/python
# coding: utf-8
import os, argparse


print('''
    \033[1;31m 
  _      _                    ______                                      _   _             
 | |    (_)                  |  ____|                                    | | (_)            
 | |     _ _ __  _   ___  __ | |__   _ __  _   _ _ __ ___   ___ _ __ __ _| |_ _  ___  _ __  
 | |    | | '_ \| | | \ \/ / |  __| | '_ \| | | | '_ ` _ \ / _ \ '__/ _` | __| |/ _ \| '_ \ 
 | |____| | | | | |_| |>  <  | |____| | | | |_| | | | | | |  __/ | | (_| | |_| | (_) | | | |
 |______|_|_| |_|\__,_/_/\_\ |______|_| |_|\__,_|_| |_| |_|\___|_|  \__,_|\__|_|\___/|_| |_|
                                                                                            
                                                                                           
\033[1;m
    \033[1;33mTwitter: @p33rl | GitHub.com/Und3r-r00t
    Coded By Und3r-r00t | Website: xRedTeam.com
    Example: python Enumeration.py -r report\033[1;m
    ''')

parser = argparse.ArgumentParser(description="test")
parser.add_argument('-r', required=False, default=None, help='Report.')


args = vars(parser.parse_args())


report = args['r']

print('\033[1;31m=============== SYSTEM  ==============\033[1;m')

print('\033[1;33m=============== Kernel information  ==============\033[1;m')
uname = os.popen('uname -a').read()
print(uname)

print('\033[1;33m============== Kernel information (continued)  =============\033[1;m')
proc = os.popen('cat /proc/version 2>/dev/null').read()
print(proc)

print('\033[1;33m============== Specific release information  =============\033[1;m')
release = os.popen('cat /etc/*-release').read()
print(release)

print('\033[1;33m============== Hostname  =============\033[1;m')
hostnamef = os.popen('hostname').read()
print(hostnamef)

print('\033[1;33m============== Current user/group info  =============\033[1;m')
detailsuser = os.popen('id 2>/dev/null').read()
print(detailsuser)

print('\033[1;33m============== last logged on user information  =============\033[1;m')
lastlogin = os.popen('lastlog 2>/dev/null |grep -v "Never" 2>/dev/null').read()
print(lastlogin)

print('\033[1;33m============== who else is logged on  =============\033[1;m')
whologed = os.popen('w').read()
print(whologed)

print('\033[1;33m============== Group memberships  =============\033[1;m')
groupmemberships = os.popen('for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null').read()
print(groupmemberships)

print('\033[1;33m============== Contents of /etc/passwd  =============\033[1;m')
etcpasswd = os.popen('cat /etc/passwd').read()
print(etcpasswd)

print('\033[1;33m============== Shadow file  =============\033[1;m')
shadowfile = os.popen('cat /etc/shadow').read()
print(shadowfile)

print('\033[1;33m============== master.passwd file  =============\033[1;m')
masterfile = os.popen('cat /etc/master.passwd').read()
print(masterfile)

print('\033[1;33m============== Sudoers configuration (condensed)  =============\033[1;m')
sudoersc = os.popen("grep -v -e '^$' /etc/sudoers").read()
print(sudoersc)

print('\033[1;33m============== We can sudo without supplying a password  =============\033[1;m')
sudopass = os.popen("echo '' | sudo -S -l -k 2>/dev/null").read()
print(sudopass)

print('\033[1;33m============== We can sudo when supplying a password  =============\033[1;m')
sudowpass = os.popen('echo $userpassword | sudo -S -l -k 2>/dev/null').read()
print(sudowpass)

print('\033[1;33m============== Accounts that have recently used sudo  =============\033[1;m')
accsudo = os.popen('find /home -name .sudo_as_admin_successful').read()
print(accsudo)

print('\033[1;33m============== Checks to see if root Home Directory is Accessible  =============\033[1;m')
homeroot = os.popen('ls -ahl /root/').read()
print(homeroot)

print('\033[1;33m============== Permissions on /home directories   =============\033[1;m')
homeper = os.popen('ls -ahl /home/').read()
print(homeper)

print('\033[1;33m============== Files not owned by user but writable by group  =============\033[1;m')
filegroup = os.popen('find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null').read()
print(filegroup)

print('\033[1;33m============== Files owned by our user  =============\033[1;m')
fileuser = os.popen('find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null').read()
print(fileuser)


print('\033[1;33m============== Hidden files  =============\033[1;m')
hiddendile = os.popen('find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null').read()
print(hiddendile)


print('\033[1;33m============== World-readable files within /home  =============\033[1;m')
worldread = os.popen('find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null').read()
print(worldread)

print('\033[1;33m============== SSH keys/host information   =============\033[1;m')
keyshost = os.popen('find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;').read()
print(keyshost)

print('\033[1;33m============== Environment information   =============\033[1;m')
enviroments = os.popen("env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null").read()
print(enviroments)

print('\033[1;33m============== SELinux seems to be present   =============\033[1;m')
sestatus = os.popen('sestatus 2>/dev/null').read()
print(sestatus)

print('\033[1;33m============== Path information  =============\033[1;m')
pathinfo = os.popen('echo $PATH 2>/dev/null').read()
print(pathinfo)

print('\033[1;33m============== Available shells  =============\033[1;m')
shellinfo = os.popen('cat /etc/shells 2>/dev/null').read()
print(shellinfo)

print('\033[1;33m============== Current umask value  =============\033[1;m')
umaskinfo = os.popen('umask -S 2>/dev/null & umask').read()
print(umaskinfo)

print('\033[1;33m============== umask value as specified in /etc/login.defs  =============\033[1;m')
umaskdef = os.popen('grep -i "^UMASK" /etc/login.defs').read()
print(umaskdef)

print('\033[1;33m============== Password and storage information  =============\033[1;m')
passstorage = os.popen('grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null').read()
print(passstorage)


print('\033[1;31m=============== JOBS/TASKS  ==============\033[1;m')

print('\033[1;33m============== Cron jobs  =============\033[1;m')
cronjobs = os.popen('ls -la /etc/cron* 2>/dev/null').read()
print(cronjobs)

print('\033[1;33m============== World-writable cron jobs and file contents  =============\033[1;m')
cronjobwwperms = os.popen('find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;').read()
print(cronjobwwperms)

print('\033[1;33m============== Crontab contents  =============\033[1;m')
crontabvalue = os.popen('cat /etc/crontab 2>/dev/null').read()
print(crontabvalue)

print('\033[1;33m============== Anything interesting in /var/spool/cron/crontabs  =============\033[1;m')
crontabvar = os.popen('ls -la /var/spool/cron/crontabs 2>/dev/null').read()
print(crontabvar)

print('\033[1;33m============== Anacron jobs and associated file permissions  =============\033[1;m')
anacronjobs = os.popen('ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null').read()
print(anacronjobs)

print('\033[1;33m============== When were jobs last executed (/var/spool/anacron contents)  =============\033[1;m')
anacrontab = os.popen('ls -la /var/spool/anacron 2>/dev/null').read()
print(anacrontab)

print('\033[1;33m============== Jobs held by all users  =============\033[1;m')
cronother = os.popen('cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null').read()
print(cronother)

print('\033[1;33m============== Enable thorough tests to see inactive timers  =============\033[1;m')
systemdtimers = os.popen('systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null').read()
print(systemdtimers)


print('\033[1;31m=============== NETWORKING  ==============\033[1;m')

print('\033[1;33m============== Network and IP info  =============\033[1;m')
nicinfo = os.popen('/sbin/ifconfig -a 2>/dev/null').read()
print(nicinfo)

print('\033[1;33m============== nic information (using ip)  =============\033[1;m')
nicinfoip = os.popen('/sbin/ip a 2>/dev/null').read()
print(nicinfoip)


print('\033[1;33m============== ARP history  =============\033[1;m')
asrphs = os.popen('arp -a 2>/dev/null').read()
print(asrphs)

print('\033[1;33m============== ARP info ip  =============\033[1;m')
arpinfoip = os.popen('ip n 2>/dev/null').read()
print(arpinfoip)

print('\033[1;33m============== Nameserver  =============\033[1;m')
nsinfo = os.popen('grep "nameserver" /etc/resolv.conf 2>/dev/null').read()
print(nsinfo)

print('\033[1;33m============== Nameserver(s)  =============\033[1;m')
nsinfosysd = os.popen('systemd-resolve --status 2>/dev/null').read()
print(nsinfosysd)

print('\033[1;33m============== Default route  =============\033[1;m')
defroute = os.popen('route 2>/dev/null | grep default').read()
print(defroute)

print('\033[1;33m============== Default route (ip)  =============\033[1;m')
defrouteip = os.popen('ip r 2>/dev/null | grep default').read()
print(defrouteip)

print('\033[1;33m============== Listening TCP  =============\033[1;m')
defrouteip = os.popen('netstat -antp 2>/dev/null').read()
defrouteip1 = os.popen('ss -t 2>/dev/null').read()
print(defrouteip)
print(defrouteip1)

print('\033[1;33m============== Listening UDP  =============\033[1;m')
udpservs = os.popen('netstat -anup 2>/dev/null').read()
print(udpservs)
udpservsip = os.popen('ip -u 2>/dev/null').read()
print(udpservsip)


print('\033[1;31m=============== SERVICES  ==============\033[1;m')

print('\033[1;33m============== Running processes  =============\033[1;m')
psaux = os.popen('ps aux 2>/dev/null').read()
print(psaux)

print('\033[1;33m============== Process binaries and associated permissions  =============\033[1;m')
procperm = os.popen("ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null").read()
print(procperm)

print('\033[1;33m============== Contents of /etc/inetd.conf  =============\033[1;m')
inetdread = os.popen('cat /etc/inetd.conf 2>/dev/null').read()
print(inetdread)

print('\033[1;33m============== The related inetd binary permissions  =============\033[1;m')
inetdbinperms = os.popen("awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null").read()
print(inetdbinperms)

print('\033[1;33m============== Contents of /etc/xinetd.conf  =============\033[1;m')
xinetdread = os.popen('cat /etc/xinetd.conf 2>/dev/null').read()
print(xinetdread)

print('\033[1;33m============== /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below  =============\033[1;m')
xinetdincd = os.popen('grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null').read()
print(xinetdincd)

print('\033[1;33m============== The related xinetd binary permissions  =============\033[1;m')
xinetdbinperms = os.popen("awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null").read()
print(xinetdbinperms)

print('\033[1;33m============== /etc/init.d/ binary permissions  =============\033[1;m')
initdread = os.popen('ls -la /etc/init.d 2>/dev/null').read()
print(initdread)

print('\033[1;33m============== /etc/init.d/ files not belonging to root  =============\033[1;m')
initdperms = os.popen('find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null').read()
print(initdperms)

print('\033[1;33m============== /etc/rc.d/init.d binary permissions  =============\033[1;m')
rcdread = os.popen('ls -la /etc/rc.d/init.d 2>/dev/null').read()
print(rcdread)

print('\033[1;33m============== /etc/rc.d/init.d files not belonging to root  =============\033[1;m')
rcdperms = os.popen('find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null').read()
print(rcdperms)

print('\033[1;33m============== /usr/local/etc/rc.d binary permissions  =============\033[1;m')
usrrcdread = os.popen('ls -la /usr/local/etc/rc.d 2>/dev/null').read()
print(usrrcdread)

print('\033[1;33m==============  /usr/local/etc/rc.d files not belonging to root  =============\033[1;m')
usrrcdperms = os.popen('find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null').read()
print(usrrcdperms)

print('\033[1;33m==============  /etc/init/ config file permissions  =============\033[1;m')
initread = os.popen('ls -la /etc/init/ 2>/dev/null').read()
print(initread)

print('\033[1;33m==============  /etc/init/ config files not belonging to root =============\033[1;m')
initperms = os.popen('find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null').read()
print(initperms)

print('\033[1;33m==============  /lib/systemd/* config file permissions =============\033[1;m')
systemdread = os.popen('ls -lthR /lib/systemd/ 2>/dev/null').read()
print(systemdread)

print('\033[1;33m==============  /lib/systemd/* config files not belonging to root =============\033[1;m')
systemdperms = os.popen('find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null').read()
print(systemdperms)


print('\033[1;31m=============== SOFTWARE  ==============\033[1;m')

print('\033[1;33m==============  Sudo Version =============\033[1;m')
sudover = os.popen('sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null').read()
print(sudover)

print('\033[1;33m==============  Mysql Version =============\033[1;m')
mysqlver = os.popen('mysql --version 2>/dev/null').read()
print(mysqlver)

print('\033[1;33m==============  Checks to See if default root/root credentials will get us a Connection =============\033[1;m')
mysqlconnect = os.popen('mysqladmin -uroot -proot version 2>/dev/null').read()
print(mysqlconnect)

print('\033[1;33m==============  Checks to See if can connect to the local MYSQL service as root and without a Password =============\033[1;m')
mysqlconnectnopass = os.popen('mysqladmin -uroot version 2>/dev/null').read()
print(mysqlconnectnopass)

print('\033[1;33m==============  Postgres version =============\033[1;m')
postgver = os.popen('psql -V 2>/dev/null').read()
print(postgver)

print('\033[1;33m==============   connect to Postgres DB template0 as user postgres with no password  =============\033[1;m')
postcon1 = os.popen("psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version").read()
print(postcon1)
print('\033[1;33m==============  can connect to Postgres DB template1 as user postgres with no password  =============\033[1;m')
postcon11 = os.popen("psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version").read()
print(postcon11)
print('\033[1;33m==============  can connect to Postgres DB template0 as user psql with no password  =============\033[1;m')
postcon2 = os.popen("psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version").read()
print(postcon2)
print('\033[1;33m==============  can connect to Postgres DB template1 as user psql with no password  =============\033[1;m')
postcon22 = os.popen("postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version").read()
print(postcon22)




print('\033[1;31m=============== Apache version  ==============\033[1;m')

apachever = os.popen('apache2 -v 2>/dev/null; httpd -v 2>/dev/null').read()
print(apachever)

print('\033[1;33m==============  Apache user configuration =============\033[1;m')
apacheusr = os.popen("grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null").read()
print(apacheusr)

print('\033[1;33m==============  Installed Apache modules =============\033[1;m')
apachemodules = os.popen('apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null').read()
print(apachemodules)

print('\033[1;33m==============  htpasswd found - could contain passwords =============\033[1;m')
htpasswd = os.popen('find / -name .htpasswd -print -exec cat {} \; 2>/dev/null').read()
print(htpasswd)

print('\033[1;33m==============  www home dir contents =============\033[1;m')
apachehomedirs = os.popen('ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null').read()
print(apachehomedirs)


print('\033[1;31m=============== INTERESTING FILES  ==============\033[1;m')

print('\033[1;33m==============  Useful file locations =============\033[1;m')
usefulfile = os.popen('which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null').read()
print(usefulfile)

print('\033[1;33m==============  Installed compilers =============\033[1;m')
compiler = os.popen("dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null").read()
print(compiler)

print('\033[1;33m==============  Can we read/write sensitive files =============\033[1;m')
readsensitive = os.popen('ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null').read()
print(readsensitive)

print('\033[1;33m============== SUID files =============\033[1;m')
findsuid = os.popen('find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;').read()
print(findsuid)

print('\033[1;33m============== Possibly interesting SUID files =============\033[1;m')
intsuid = os.popen('find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null').read()
print(intsuid)

print('\033[1;33m============== World-writable SUID files =============\033[1;m')
wwsuid = os.popen('find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;').read()
print(wwsuid)

print('\033[1;33m============== World-writable SUID files owned by root =============\033[1;m')
wwsuidrt = os.popen('find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;').read()
print(wwsuidrt)

print('\033[1;33m============== SGID files =============\033[1;m')
findsgid = os.popen('find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;').read()
print(findsgid)

print('\033[1;33m============== Possibly interesting SGID files =============\033[1;m')
intsgid = os.popen('find / -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null').read()
print(intsgid)

print('\033[1;33m============== World-writable SGID files =============\033[1;m')
wwsgid = os.popen('find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;').read()
print(wwsgid)

print('\033[1;33m============== World-writable SGID files owned by root =============\033[1;m')
wwsgidrt = os.popen('find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;').read()
print(wwsgidrt)

print('\033[1;33m============== Files with POSIX capabilities set =============\033[1;m')
fileswithcaps = os.popen('getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null').read()
print(fileswithcaps)

print('\033[1;33m============== Users with specific POSIX capabilities =============\033[1;m')
userswithcaps = os.popen("grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null").read()
print(userswithcaps)

print('\033[1;33m============== Capabilities associated with the current user =============\033[1;m')
matchedcaps = os.popen("echo -e '$userswithcaps' | grep \`whoami\` | awk '{print $1}' 2>/dev/null").read()
print(matchedcaps)

print('\033[1;33m============== Files with the same capabilities associated with the current user (You may want to try abusing those capabilties) =============\033[1;m')
matchedfiles = os.popen('echo -e "$matchedcaps" | while read -r cap ; do echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null').read()
print(matchedfiles)

print('\033[1;33m============== Permissions of files with the same capabilities associated with the current user =============\033[1;m')
matchedfilesperms = os.popen("echo -e '$matchedfiles' | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null").read()
print(matchedfilesperms)

print('\033[1;33m============== User/Group writable files with the same capabilities associated with the current user =============\033[1;m')
writablematchedfiles = os.popen("echo -e '$matchedfiles' | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null").read()
print(writablematchedfiles)

print('\033[1;33m============== Private SSH keys found! =============\033[1;m')
privatekeyfiles = os.popen('grep -rl "PRIVATE KEY-----" /home 2>/dev/null').read()
print(privatekeyfiles)

print('\033[1;33m============== AWS secret keys found! =============\033[1;m')
awskeyfiles = os.popen('grep -rli "aws_secret_access_key" /home 2>/dev/null').read()
print(awskeyfiles)

print('\033[1;33m============== Git credentials saved on the machine =============\033[1;m')
gitcredfiles = os.popen('find / -name ".git-credentials" 2>/dev/null').read()
print(gitcredfiles)

print('\033[1;33m============== World-writable files (excluding /proc and /sys) =============\033[1;m')
wwfiles = os.popen('find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;').read()
print(wwfiles)

print('\033[1;33m============== Plan file permissions and contents =============\033[1;m')
usrplan = os.popen('usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;').read()
print(usrplan)
bsdusrplan = os.popen('find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;').read()
print(bsdusrplan)

print('\033[1;33m============== rhost config file(s) and file contents =============\033[1;m')
rhostsusr = os.popen('find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;').read()
print(rhostsusr)
bsdrhostsusr = os.popen('find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;').read()
print(bsdrhostsusr)

print('\033[1;33m============== Hosts.equiv file and contents =============\033[1;m')
rhostssys = os.popen('find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;').read()
print(rhostssys)

print('\033[1;33m============== NFS config details =============\033[1;m')
nfsexports = os.popen('ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null').read()
print(nfsexports)

print('\033[1;33m============== NFS displaying partitions and filesystems - you need to check if exotic filesystems =============\033[1;m')
fstab = os.popen('cat /etc/fstab 2>/dev/null').read()
print(fstab)

print('\033[1;33m============== Looks like there are credentials in /etc/fstab =============\033[1;m')
fstab1 = os.popen("grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,'');sub(/\,.*/,'')}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,'');sub(/\,.*/,'')}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,'');sub(/\,.*/,'')}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null").read()
print(fstab1)
fstabcred = os.popen("grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,'');sub(/\,.*/,'')}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null").read()
print(fstabcred)

print('\033[1;33m============== All *.conf files in /etc (recursive 1 level) =============\033[1;m')
allconf = os.popen('find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null').read()
print(allconf)

print('\033[1;33m============== Current users history files =============\033[1;m')
usrhist = os.popen('ls -la ~/.*_history 2>/dev/null').read()
print(usrhist)

print('\033[1;33m============== Roots history files are accessible =============\033[1;m')
roothist = os.popen('ls -la /root/.*_history 2>/dev/null').read()
print(roothist)

print('\033[1;33m============== Location and contents (if accessible) of .bash_history file(s) =============\033[1;m')
checkbashhist = os.popen('find /home -name .bash_history -print -exec cat {} 2>/dev/null \;').read()
print(checkbashhist)

print('\033[1;33m============== Any interesting mail in /var/mail =============\033[1;m')
readmail = os.popen('ls -la /var/mail 2>/dev/null').read()
print(readmail)

print('\033[1;33m============== We can read /var/mail/root! (snippet below) =============\033[1;m')
readmailroot = os.popen('head /var/mail/root 2>/dev/null').read()
print(readmailroot)

print("\033[1;33m============== Looks like we're in a Docker container =============\033[1;m")
dockercontainer = os.popen('grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null').read()
print(dockercontainer)

print("\033[1;33m============== Looks like we're hosting Docker =============\033[1;m")
dockerhost = os.popen('docker --version 2>/dev/null; docker ps -a 2>/dev/null').read()
print(dockerhost)

print("\033[1;33m============== We're a member of the (docker) group - could possibly misuse these rights =============\033[1;m")
dockergrp = os.popen('id | grep -i docker 2>/dev/null').read()
print(dockergrp)

print('\033[1;33m============== Anything juicy in the Dockerfile =============\033[1;m')
dockerfiles = os.popen('find / -name Dockerfile -exec ls -l {} 2>/dev/null \;').read()
print(dockerfiles)

print('\033[1;33m============== Anything juicy in docker-compose.yml =============\033[1;m')
dockeryml = os.popen('find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;').read()
print(dockeryml)

print("\033[1;33m============== Looks like we're in a lxc container =============\033[1;m")
lxccontainer = os.popen('grep -qa container=lxc /proc/1/environ 2>/dev/null').read()
print(lxccontainer)

print("\033[1;33m============== We're a member of the (lxd) group - could possibly misuse these rights =============\033[1;m")
lxdgroup = os.popen('id | grep -i lxd 2>/dev/null').read()
print(lxdgroup)


print('\033[1;31m=============== SCAN COMPLETE  ==============\033[1;m')

if report is None:
	pass
else:
	f = open("report.txt", "w")
	f.write(files)
	f.write(app)
	f.close()
