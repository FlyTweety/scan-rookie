

import scapy.all as sc

from host_state import HostState
from syn_scan_async_new import SYN_SCAN_SEQ_NUM, SYN_SCAN_SOURCE_PORT
import utils

class PacketProcessor(object):

    def __init__(self, host_state):

        assert isinstance(host_state, HostState)
        self._host_state = host_state

    def process_packet(self, pkt):

        utils.safe_run(self._process_packet_helper, args=[pkt])

    def _process_packet_helper(self, pkt):
        
        # SYN-ACK response to SYN scans
        if sc.TCP in pkt and pkt[sc.TCP].flags == 'SA' and sc.IP in pkt: # This is a SYN-ACK
            tcp_layer = pkt[sc.TCP]
            if tcp_layer.dport == SYN_SCAN_SOURCE_PORT and tcp_layer.ack == SYN_SCAN_SEQ_NUM + 1: # This is response to our scan
                return self._process_syn_scan(pkt)

    # Modified
    def _process_syn_scan(self, pkt):

        src_ip = pkt[sc.IP].src
        dst_ip = pkt[sc.IP].dst
        device_port = pkt[sc.TCP].sport

        utils.log('[SYN Scan Response] From Src IP = {} Dst IP = {} Src Port = {}'.format(
            src_ip, dst_ip, device_port
        ))

        self._host_state.received_ip_port_info.append({"ip": src_ip, "port": device_port, "info": "null"})

        #print("self._host_state.received_ip_port_info = ", self._host_state.received_ip_port_info)
