import ast
import json
from scapy.all import rdpcap, sniff

class Bacon:

    def __init__(self, file, target, sniff, interface, update, log, dictionary="src/bacon/files/ap_dict.ast"):
        self.file = file
        self.target = target
        self.sniff = sniff
        self.interface = interface
        self.update = update
        self.log = log
        self.dict_file = dictionary
        self.list_dict = {}
        self.ap_list = []
        self.prompt = False

    def find_beacon(self, packet):
        """
        Parse rdpcap packet for beacon frames

        Parameters:
            packet (scapy pcap packet): Packet contained in scapy pcap

        Returns:
            id_list (arr): List of IDs
            ssid (str): SSID of system
        """
        ssid = None
        id_list = []
        if packet.type == 0 and packet.subtype == 8:  # If packet is beacon
            if packet.info not in self.ap_list:  # If SSID has not been parsed
                ssid = packet.info
                self.ap_list.append(ssid)  # Add SSID to list
                id_list = []
                for i in range(0,20):  # Iterate through layers. Layers are dynamic but I can't figure out how to get a length of them.
                    try:
                        frame = packet.getlayer(i)
                        id_list.append(frame.ID)  # Gets tag number and adds to list
                    except AttributeError:
                        continue
                    except Exception as e:
                        self.log.error("Unhandled Exception")
                        self.log.error(e)
                        id_list = None
                        ssid = None
        else:
            id_list = None
            ssid = None
        return ssid, id_list

    def parse_pcap(self, pcap):
        """
        Parse rdpcap packet for beacon frames

        Parameters:
            pcap (scapy pcap): Packet contained in scapy pcap

        Returns:
            None
        """
        for packet in pcap:
            ssid, id_list = self.find_beacon(packet)
            if ssid is None or id_list is None:
                continue
            try:
                ssid = ssid.decode('utf-8')
                # Jank fix for unadvertised/unknown SSIDs
                if b"\x00\x00\x00\x00" in ssid.encode():
                    ssid = "UNK"
                self.log.info(f"Possible Firmware Version(s) for {ssid}:\n {self.list_dict[str(id_list)]}")
            except KeyError:  # Tries to get firmware version from user to add to dictionary
                #self.log.info(e)
                self.log.info(f"Unable to match firmware for: {(packet.info.decode('utf-8'))}")
            except Exception as e:
                self.log.error("Unhandled Exception")
                self.log.error(e)
            return None

    def load_dictionary(self):
        """
        Load beacon => firmware version relation dictionary

        Returns:
            None
        """
        with open(self.dict_file, 'r') as f:
            data = f.read()
            try:
                self.list_dict=ast.literal_eval(data)
                self.log.info(f"Loaded dictionary with: {len(self.list_dict)} Keys")
            except Exception as e:
                self.log.error(e)
        return None

    def update_dictionary(self):
        #TODO: Add ability to update dictionary. Maybe make this its own script?
        pass

    def sniff_traffic(self):
        #TODO: Add ability to sniff and parse traffic.
        pass

    def run(self):
        """
        Run bacon finger printer

        Returns:
            None
        """
        self.log.info("Loading Dictionary")
        self.load_dictionary()
        pcap = rdpcap(self.file)
        self.parse_pcap(pcap)
        return None
