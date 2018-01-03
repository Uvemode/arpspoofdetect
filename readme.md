Small fork from uiuseclab's arpspoofdetect for Gnome/linux. 

Changed features:

  - Gnome notification.
  - Python 3 compatibility.
  - Does not ask input, log file and interface are hand-coded.
  - Plays custom audio file as alarm to raise awareness. (I use mpv with .wav format)
  
  
Attention:

Since the script must run as root, in order to obtain a notification with Gnome your must specify your username(non-root) and the DBUS_SESSION_BUS_ADDRESS at the subprocess call, which can be obtain at a shell with "echo $DBUS_SESSION_BUS_ADDRESS", then insert the path at the script, line 79.


ARP Spoof Detect
=========

ARP Spoof Detect is a simple, lightweight ARP spoofing detector script that checks if your network is being ARP spoofed.

The script is easy to set up and safe to run in background. Once an ARP spoof attack is detected, a system notification will be sent to the user, and corresponding information will be logged in the log file.

Features
----
  - Detect ARP reply messages in the network.
  - Detect if a machine has launched ARP spoof attack in the network.
  - Log all ARP reply messages and potential ARP spoof attacks in the log file.
  - Send system notification to user once such attack occurs. (Currently only supported in Mac OS X)

Dependencies
-----------
ARP Spoof Detect requires the following two packages to function on any machines.

* [Scapy] - Powerful packet manipulation package.
* [Netifaces] - Python network interface reader.

On Ubuntu machine, it is easy to install these two packages by doing
```
apt-get install python-scapy python-netifaces
```

How To Run
----
First make sure detect_arpspoof.py is executable. Otherwise run
```
chmod +x detect_arpspoof.py
./detect_arpspoof.py
```
or simply you can just run
```
python detect_arpspoof.py
```
Please make sure that the script is run as the root user, as root privilege is required to operate network interfaces.

Now, choose the location where you wish to store your log file, or press enter to use the default file name. 

```
Please input desired log file name. [spoof.log]
```

Once you've selected the log file location, you will be prompted to choose the network interface on which you would like to detect ARP spoofing. For most cases, this should be the default network interface you use to access Internet. A list of available interfaces on your machine is offered for your convenience.

```
Please select the interface you wish to use. ['lo0', 'gif0', 'stf0', 'en0', 'en1', 'en2', 'bridge0', 'p2p0', 'vnic0', 'vnic1']
```

Once proper interfaces is selected, and no other error occurs, you will see
```
ARP Spoofing Detection Started. Any output is redirected to log file.
```

[Scapy]:http://www.secdev.org/projects/scapy/
[Netifaces]:https://pypi.python.org/pypi/netifaces
