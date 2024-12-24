import socket
import struct
from dataclasses import dataclass
from typing import Optional, Tuple
import logging

@dataclass
class PacketInfo:
    """
    Data structure for storing parsed packet information.
    """
    protocol: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    payload: bytes
    timestamp: float

class PacketAnalyzer:
    """
    A class to capture and analyze network packets.
    """
    def __init__(self):
        self.sock = None
        self.running = False
        self.setup_logging()
    
    def setup_logging(self):
        """
        Configure logging for packet capture and analysis.
        """
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='packet_analysis.log'
        )
    
    def start_capture(self):
        """
        Start capturing packets.
        Requires root/administrator privileges.
        """
        try:
            self.sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(0x0003)
            )
        except PermissionError:
            logging.error("Root privileges are required for packet capture.")
            raise
        
        self.running = True
        logging.info("Packet capture started.")
        
        while self.running:
            try:
                packet = self.sock.recvfrom(65535)[0]
                packet_info = self.analyze_packet(packet)
                if packet_info:
                    self.log_packet(packet_info)
            except Exception as e:
                logging.error(f"Error capturing packet: {e}")
    
    def stop_capture(self):
        """
        Stop capturing packets and release resources.
        """
        self.running = False
        if self.sock:
            self.sock.close()
            logging.info("Packet capture stopped.")
        else:
            logging.warning("Socket was not initialized.")
    
    def analyze_packet(self, packet: bytes) -> Optional[PacketInfo]:
        """
        Analyze a raw packet and extract useful details.
        """
        try:
            eth_header = packet[:14]
            eth_data = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth_data[2])
            
            if eth_protocol == 0x0800:  # IPv4
                ip_header = packet[14:34]
                ip_data = struct.unpack("!BBHHHBBH4s4s", ip_header)
                source_ip = socket.inet_ntoa(ip_data[8])
                dest_ip = socket.inet_ntoa(ip_data[9])
                protocol = ip_data[6]
                
                if protocol == 6:  # TCP
                    tcp_header = packet[34:54]
                    tcp_data = struct.unpack("!HHLLBBHHH", tcp_header)
                    source_port = tcp_data[0]
                    dest_port = tcp_data[1]
                    payload = packet[54:]
                    
                    return PacketInfo(
                        protocol="TCP",
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        source_port=source_port,
                        dest_port=dest_port,
                        payload=payload,
                        timestamp=socket.time.time()
                    )
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")
            return None
    
    def log_packet(self, packet_info: PacketInfo):
        """
        Log the details of a captured packet.
        """
        logging.info(
            f"{packet_info.protocol} Packet | "
            f"Src: {packet_info.source_ip}:{packet_info.source_port} -> "
            f"Dst: {packet_info.dest_ip}:{packet_info.dest_port} | "
            f"Payload Size: {len(packet_info.payload)} bytes"
        )
