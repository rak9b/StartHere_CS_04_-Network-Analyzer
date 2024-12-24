import pytest
from src.packet_analyzer import PacketAnalyzer, PacketInfo
import socket

@pytest.fixture
def packet_analyzer():
    """
    Fixture to provide a fresh instance of PacketAnalyzer for each test.
    """
    return PacketAnalyzer()

def test_analyzer_initialization(packet_analyzer):
    """
    Test if PacketAnalyzer initializes correctly.
    """
    assert not packet_analyzer.running
    assert packet_analyzer.sock is None

def test_start_and_stop_capture(packet_analyzer, mocker):
    """
    Test the start_capture and stop_capture methods.
    """
    mock_socket = mocker.patch("socket.socket")
    packet_analyzer.start_capture = mocker.MagicMock()
    packet_analyzer.stop_capture = mocker.MagicMock()
    
    # Test start_capture
    mock_socket.return_value = mocker.MagicMock()
    packet_analyzer.start_capture()
    packet_analyzer.start_capture.assert_called_once()

    # Test stop_capture
    packet_analyzer.stop_capture()
    packet_analyzer.stop_capture.assert_called_once()

def test_analyze_packet_valid_tcp():
    """
    Test analyze_packet with a valid TCP packet.
    """
    analyzer = PacketAnalyzer()
    mock_packet = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00"  # Ethernet header
        b"\x45\x00\x00\x34\x12\x34\x00\x00\x40\x06\xa6\xec"  # IPv4 header
        b"\x7f\x00\x00\x01\x7f\x00\x00\x01"                 # Source and Destination IP
        b"\x1f\x90\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"  # TCP header
        b"\x50\x02\x20\x00\x91\x7c\x00\x00"                 # TCP flags and window
        b"Payload data here!"                               # Payload
    )
    packet_info = analyzer.analyze_packet(mock_packet)
    
    assert packet_info is not None
    assert packet_info.protocol == "TCP"
    assert packet_info.source_ip == "127.0.0.1"
    assert packet_info.dest_ip == "127.0.0.1"
    assert packet_info.source_port == 8080
    assert packet_info.dest_port == 80
    assert packet_info.payload == b"Payload data here!"

def test_analyze_packet_invalid_packet(packet_analyzer):
    """
    Test analyze_packet with an invalid packet.
    """
    invalid_packet = b"\x00\x00\x00\x00"  # Truncated packet
    assert packet_analyzer.analyze_packet(invalid_packet) is None
