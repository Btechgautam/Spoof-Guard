#!/usr/bin/env python



import urllib, httplib, smtplib, os, sys, time
from scapy.all import *
from optparse import OptionParser

parser = OptionParser()
parser.add_option('-p', '--myip', dest='myip', default='127.0.0.1', help='Set your IP Address')
parser.add_option('-b', '--broadcast', dest='broadcast', default='127.0.0.255', help='Set broadcast IP Address')
parser.add_option('-f', '--file', dest='fname', default='found.txt')

(options, args) = parser.parse_args()

global fname, req, hws, myip, broadcast

path = os.getcwd()

myip = options.myip
fname = "%s/%s" %(path, options.fname)
broadcast = options.broadcast
req = []
hws = []

def Search(ip, hw, dip):
    now = time.strftime("%d-%m-%Y %H:%M:%S")
    if dip == broadcast:
        if not hw in hws:
            arq = open(fname, "a")
            arq.write("[%s] ARP sent to broadcast address [%s]\n" %(now, hw))
            arq.close()
            hws.append(hw)
        return "ARP sent to broadcast address [%s]" %hw
    if not ip in req and ip != myip:
        if not hw in hws:
            arq = open(fname, "a")
            arq.write("[%s] ARP Spoofing detect [%s]\n" %(now, hw))
            arq.close()
            hws.append(hw)
        return "ARP Spoofing detect [%s]" %hw
    else:
        if ip in req:
            req.remove(ip)

def Detect(pkt):
    sip = pkt.sprintf("%ARP.psrc%")
    dip = pkt.sprintf("%ARP.pdst%")
    shw = pkt.sprintf("%ARP.hwsrc%")
    op = pkt.sprintf("%ARP.op%")
    if sip == myip:
        req.append(dip)
    if op == 'is-at':
        return Search(sip, shw, dip)
        
sniff(prn=Detect, filter="arp", store=0)
