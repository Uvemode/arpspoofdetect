#!/usr/bin/env python
import os, time, netifaces, sys, logging
import subprocess as s
import smtplib
from sys import platform
from scapy.all import sniff

# Number of ARP replies received from a specific mac before flagging it
request_threshold = 10

# The script requires root to run. Check if user is root
if os.geteuid() != 0:
    exit("Root permisson is required to operate on network interfaces. \nNow Aborting.")

filename = "/var/log/arp_shield" # Your log file
interface = "eth0" # Your interface
alarm = "/home/uve/Documents/src/arp_shield/arp_alarm.wav" # Your audio file


# Set logging structure
logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
# Read available network interfaces
available_interfaces = netifaces.interfaces()

# Check if specified interface is valid
if not interface in available_interfaces:
    exit("Interface {} not available.".format(interface))
# Retrieve network addresses (IP, broadcast) from the network interfaces
addrs = netifaces.ifaddresses(interface)
try:
    local_ip = addrs[netifaces.AF_INET][0]["addr"]
    broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
except KeyError:
    exit("Cannot read address/broadcast address on interface {}".format(interface))

requests = []
replies_count = {}
notification_issued = []

logging.info("ARP Poisoning Detection Started on {}".format(local_ip))

def check_spoof (source, mac, destination):
    # Function checks if a specific ARP reply is part of an ARP spoof attack or not
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        # Logs ARP Reply
        logging.warning("ARP replies detected from MAC {}. Request count {}".format(mac, replies_count[mac]))

        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            logging.error("ARP Poisoning Detected from MAC Address {}".format(mac)) # Logs the attack in the log file
            # Issue OS Notification
            issue_os_notification("ARP Poisoning Detected", "Attack from {}".format(mac))
            # Add to sent list to prevent repeated notifications.
            notification_issued.append(mac)
            # Email to admin
            mail_admin()
    else:
        if source in requests:
            requests.remove(source)

def packet_filter (packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == local_ip:
        requests.append(dest)
    if operation == 'is-at':
        return check_spoof (source, source_mac, dest)

def mail_admin():
    sender = "" # Sender email
    receiver = "" # Receiver email
    subject = "ARP POISONING ALARM"
    msg = "The network is currently under an ARP poisoning attack"
    body = '\r\n'.join(['To: {}'.format(receiver), 'From: {}'.format(sender), 'Subject: {}'.format(subject), "{}".format(msg)])

    try:
        # Here you must configure the smtp server according to your service
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()
        server.starttls()
        server.login(sender, "your_password")
        server.sendmail(sender, receiver, body)
        logging.info("Email sent to the admin")
    except as e:
         logging.error("Couldn't send email to admin")
         logging.error("{}".format(e))

def issue_os_notification(title, content):
    # Gnome notification
    command = "sudo -u uve DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus notify-send \'{}\' \'{}\'".format(title, content)
    s.call([command], shell=True)
    # Audio file, substitute mpv and wave file with your choice
    null_output = open("/dev/null", 'w')
    s.call(["mpv", alarm], stdout=null_output, stderr=s.STDOUT) 

print("ARP Poisoning Detection Started. Any output is redirected to log file.")
# Rely on scapy sniff function to do the hard job - sniffing packets.
sniff(filter = "arp", prn = packet_filter, store = 0)

