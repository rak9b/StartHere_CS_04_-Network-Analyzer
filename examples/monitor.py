from src.packet_analyzer import PacketAnalyzer
import signal
import sys

def graceful_exit(analyzer: PacketAnalyzer):
    """
    Handle termination signals to stop packet capture cleanly.
    """
    print("\nStopping packet capture...")
    analyzer.stop_capture()
    print("Packet capture stopped. Exiting.")
    sys.exit(0)

def main():
    """
    Example usage of PacketAnalyzer for monitoring network traffic.
    """
    print("Starting network packet analyzer...")
    analyzer = PacketAnalyzer()
    
    # Handle termination signals gracefully
    signal.signal(signal.SIGINT, lambda sig, frame: graceful_exit(analyzer))
    signal.signal(signal.SIGTERM, lambda sig, frame: graceful_exit(analyzer))
    
    try:
        analyzer.start_capture()
    except PermissionError:
        print("Error: Root/administrator privileges are required to capture packets.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        analyzer.stop_capture()

if __name__ == "__main__":
    main()
