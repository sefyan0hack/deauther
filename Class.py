from scapy.all import RadioTap,Dot11,Dot11Deauth,Dot11Elt,Dot11EltRates,Dot11EltRates,Dot11EltHTCapabilities
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
    
    def ProbeReq(wifi :WiFi):
        # RadioTap layer
        radiotap = RadioTap(
            version=0,
            pad=0,
            Rate=1.0,  # Mbps
            notdecoded="\\xc6\x00"
        )

        # 802.11-FCS layer
        dot11_fcs = Dot11(
            subtype=0x04,  # Probe Request
            type=0,        # Management
            proto=0,
            FCfield="",
            ID=0,
            addr1=wifi.bssid,
            addr2="18:a6:f7:0d:40:6b",
            addr3=wifi.bssid,
            SC=61872,
        )
        dot11_probe_req = Dot11Elt(
            ID="SSID",
            len=len(wifi.essid),
            info=wifi.essid.encode()
        )
        rates_ie = Dot11EltRates(
            ID="Supported Rates",
            len=8,
            rates=[1, 2, 5, 11, 6, 9, 12, 18]
        )
        extended_rates_ie = Dot11EltRates(
            ID="Extended Supported Rates",
            len=4,
            rates=[24, 36, 48, 54]
        )
        ht_capabilities_ie = Dot11EltHTCapabilities(
            ID="HT Capabilities",
            len=26,
            L_SIG_TXOP_Protection=0,
            Forty_Mhz_Intolerant=0,
            PSMP=0,
            DSSS_CCK=1,
            Max_A_MSDU=3839,
            Delayed_BlockAck=0,
            Rx_STBC=1,
            Tx_STBC=1,
            Short_GI_40Mhz=1,
            Short_GI_20Mhz=1,
            Green_Field=0,
            SM_Power_Save="disabled",
            Supported_Channel_Width="20Mhz+40Mhz",
            LDPC_Coding_Capability=1,
            Min_MPDCU_Start_Spacing=5,
            Max_A_MPDU_Length_Exponent=3,
            TX_Unequal_Modulation=0,
            TX_Max_Spatial_Streams=0,
            TX_RX_MCS_Set_Not_Equal=0,
            TX_MCS_Set_Defined=1,
            RX_Highest_Supported_Data_Rate=300,
            RX_MSC_Bitmask=65535,
            RD_Responder=0,
            HTC_HT_Support=0,
            MCS_Feedback=0,
            PCO_Transition_Time=0,
            PCO=0,
            Channel_Estimation_Capability=0,
            CSI_max_n_Rows_Beamformer_Supported=0,
            Compressed_Steering_n_Beamformer_Antennas_Supported=0,
            Noncompressed_Steering_n_Beamformer_Antennas_Supported=0,
            CSI_n_Beamformer_Antennas_Supported=0,
            Minimal_Grouping=0,
            Explicit_Compressed_Beamforming_Feedback=0,
            Explicit_Noncompressed_Beamforming_Feedback=0,
            Explicit_Transmit_Beamforming_CSI_Feedback=0,
            Explicit_Compressed_Steering=0,
            Explicit_Noncompressed_Steering=0,
            Explicit_CSI_Transmit_Beamforming=0,
            Calibration=0,
            Implicit_Trasmit_Beamforming=0,
            Transmit_NDP=0,
            Receive_NDP=0,
            Transmit_Staggered_Sounding=0,
            Receive_Staggered_Sounding=0,
            Implicit_Transmit_Beamforming_Receiving=0,
            ASEL=""
        )
        probe_request_packet = radiotap / dot11_fcs / dot11_probe_req / rates_ie / extended_rates_ie / ht_capabilities_ie
        return probe_request_packet
    
