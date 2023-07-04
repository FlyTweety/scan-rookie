"""
1 [√] Do a SYN scan on the popular ports, and on all the ports (65K, do it slowly) 
2 [√] See which which ports send us the SYN-ACK.
3 [√] For the ports discovered in Step 2, open a TCP socket, wait for a response; if there's no response within, 
  say, 5 seconds (the network is usually pretty fast on the LAN), we send a random string.
  You'd just need to use asyncio or select to do non-blocking socket I/O on Python to make things fast.
4 [ ] 改成被调用时就搞一轮，而不是一直搞，并且返回结果
"""

# Can not get device IPs, have to assign it manually

import time
import logging

from host_state import HostState
from syn_scan_async_new import SynScan
from packet_capture import PacketCapture
from packet_processor import PacketProcessor
from banner_grab import BannerGrab
import utils

def scan():
    
    host_state = HostState()
    print("initilize host_state")

    host_state.packet_processor = PacketProcessor(host_state)
    print("initilize packet_processor")

    syn_scan_thread = SynScan(host_state, scanAllPorts = True)
    syn_scan_thread.start()
    print("initilize syn_scan_thread")

    packet_capture_thread = PacketCapture(host_state)
    packet_capture_thread.start()
    print("initilize packet_capture_thread")

    #banner_grab_thread = BannerGrab(host_state)
    #banner_grab_thread.start()
    #print("initilize banner_grab_thread")

    print("start running")

    # Suppress scapy warnings
    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except Exception:
        pass


    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('')
            break
      
if __name__ == '__main__':
    scan()
