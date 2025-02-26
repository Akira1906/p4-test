# Note: 9559 is the default TCP port number on which the
# simple_switch_grpc process is listening for incoming TCP connections,
# over which a client program can send P4Runtime API messages to
# simple_switch_grpc.

# p4c --target bmv2 --arch v1model --p4runtime-files proxy.p4info.txtpb proxy.p4


#     connection_hash, connection_hash_rev, seq_diff, seq_diff_rev = compute_connection_hash(
#         src_ip, dst_ip, src_port, dst_port, protocol, cookie_value, seq_no
#     )

#     print(f"Connection Hash: {connection_hash}")
#     print(f"Reverse Connection Hash: {connection_hash_rev}")
#     print(f"Seq Diff: {seq_diff}")
#     print(f"Seq Diff Rev: {seq_diff_rev}")

# TODO try to fix the automated script
# for that try to connect ss_grpc via thrift via console
# if that works then also do it in the automated approach
# the challenge atm is: controller.py always fails somehow

import logging
import ptf.mask as mask
import ptf
import ptf.testutils as tu
from ptf.base_tests import BaseTest
import p4runtime_sh.shell as sh
# import p4runtime_shell_utils as shu
import ipaddress
import scapy
from scapy.all import Ether, IP, TCP
# shu.dump_table('ipv4_lpm')

######################################################################
# Configure logging
######################################################################


logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# NOTE: need to install behavioral model with thrift support
# cd ~/behavioral-model  # Go to BMv2 source directory
# ./autogen.sh
# ./configure --enable-debugger --with-thrift
# make -j$(nproc)
# sudo make install
# needs thrift 0.13

class DemoTumTest(BaseTest):
    
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        print("Data Plane is of type:")
        print(type(self.dataplane))

        logging.debug("DemoTUM.setUp()")
        grpc_addr = tu.test_param_get("grpcaddr")
        if grpc_addr is None:
            grpc_addr = "localhost:9559"

        grpc_addr='0.0.0.0:9559'
        my_dev1_id=0
        p4info_txt_fname = tu.test_param_get("p4info")
        p4prog_binary_fname = tu.test_param_get("config")

        sh.setup(device_id=my_dev1_id,
                grpc_addr=grpc_addr,
                election_id=(0, 1),# (high_32bits, lo_32bits)
                # config=sh.FwdPipeConfig(p4info_txt_fname, p4prog_binary_fname),
                verbose=True)
        # 1. start the P4 program of the tum approach
        # 2. start the control plane python application
        

    def tearDown(self):
        logging.debug("DemoTumTest.tearDown()")
        sh.teardown()


    # idea: test the application with an active control plane as integration test

    # but first write some unit tests, artifical but simpler 


class ProxyTest(DemoTumTest):
        

    def runTest(self):
        self.client_mac = "00:00:0a:00:01:01"  # h1 MAC
        self.attacker_mac = "00:00:0a:00:01:02"  # h2 MAC
        self.server_mac = "00:00:0a:00:01:03"  # h3 MAC
        self.switch_client_mac = "00:01:0a:00:01:01"  # s1 client MAC
        self.switch_attacker_mac = "00:01:0a:00:01:02"# s1 attacker MAC
        self.swich_server_mac = "00:01:0a:00:01:03" # s1 server MAC

        self.client_ip = "10.0.1.1"
        self.attacker_ip = "10.0.1.2"
        self.server_ip = "10.0.1.3"

        self.client_port = 1234
        self.server_port = 80
        self.attacker_port = 5555

        self.client_iface = 1  # h1 -> s1
        self.attacker_iface = 2  # h2 -> s1
        self.server_iface = 3  # h3 -> s1
        
        self.tcp_handshake()
    
    def get_packet_mask(pkt):
        pkt_mask = mask.Mask(pkt)

        pkt_mask.set_do_not_care_all()

        pkt_mask.set_care_packet(Ether, "src")
        pkt_mask.set_care_packet(Ether, "dst")
        pkt_mask.set_care_packet(IP, "src")
        pkt_mask.set_care_packet(IP, "dst")
        pkt_mask.set_care_packet(IP, "ttl")
        pkt_mask.set_care_packet(TCP, "sport")
        pkt_mask.set_care_packet(TCP, "dport")
        pkt_mask.set_care_packet(TCP, "flags")
        pkt_mask.set_care_packet(TCP, "seq")
        pkt_mask.set_care_packet(TCP, "ack")
        
        return pkt_mask

    def tcp_handshake(self):
        """ Simulates a proper TCP handshake between client and web server """
        print("\n[INFO] Sending TCP Handshake Packets...")

        # Step 1: SYN (Client -> Server)
        syn_pkt = (
            Ether(dst=self.switch_client_mac, src=self.client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="S")
        )
        
        tu.send_packet(self, self.client_iface, syn_pkt)
        
        # Step 2: P4 program answers SYN-ACK (Proxy -> Client)

        exp_pkt = (
            Ether(dst=self.client_mac, src=self.client_mac, type=0x0800) /
            IP(src=self.server_ip, dst=self.client_ip, ttl=63, proto=6, id=1, flags=0) /
            TCP(sport=self.server_port, dport=self.client_port, seq=2030043157, ack=1, flags="SA", window=8192)
        )

        pkt_mask = self.get_packet_mask(exp_pkt)
        
        tu.verify_packet(self, pkt_mask, self.client_iface)
        
        # Step 3: Correct ACK answer from the client
        
        ack_pkt = (
            Ether(dst=self.client_mac, src=self.switch_client_mac, type=0x0800) /
            IP(src=self.client_ip, dst=self.server_ip, ttl=64, proto=6, id=1, flags=0) /
            TCP(sport=self.client_port, dport=self.server_port, flags="A", seq=1, ack=2030043158, window=8192)
        )
        
        tu.send_packet(self, self.client_iface, ack_pkt)
        
        # Step 4: Handshake between Switch and Server
        # TODO: finish this handshake and finally finish the whole test suite

    def malicious_packets(self):
        """ Sends malicious packets from the attacker to the web server """
        print("\n[INFO] Sending Malicious Packets from Attacker...")

        # Malicious SYN flood attack
        for i in range(5):
            syn_flood_pkt = tu.simple_tcp_packet(
                eth_src=self.attacker_mac, eth_dst=self.switch_mac,
                ip_src=self.attacker_ip, ip_dst=self.server_ip,
                tcp_sport=self.attacker_port + i, tcp_dport=self.server_port,
                tcp_flags="S", tcp_seq=1000 + i
            )
            tu.send_packet(self, self.attacker_iface, syn_flood_pkt)

        # Spoofed TCP packets
        for i in range(3):
            spoofed_pkt = tu.simple_tcp_packet(
                eth_src=self.attacker_mac, eth_dst=self.switch_mac,
                ip_src="1.2.3.4", ip_dst=self.server_ip,  # Fake IP
                tcp_sport=6666, tcp_dport=self.server_port,
                tcp_flags="PA", tcp_seq=2000 + i, tcp_ack=999
            )
            tu.send_packet(self, self.attacker_iface, spoofed_pkt)

    def valid_packet_sequence(self):
        """ Sends a short series of valid packets from the client """
        print("\n[INFO] Sending Valid Data Packets from Client...")

        for i in range(3):
            data_pkt = tu.simple_tcp_packet(
                eth_src=self.client_mac, eth_dst=self.switch_mac,
                ip_src=self.client_ip, ip_dst=self.server_ip,
                tcp_sport=self.client_port, tcp_dport=self.server_port,
                tcp_flags="PA", tcp_seq=1100 + i, tcp_ack=5100,
                tcp_payload="GET / HTTP/1.1\r\nHost: server\r\n\r\n"
            )
            tu.send_packet(self, self.client_iface, data_pkt)

# class WhitelistingTest(DemoTumTest):
#     def runTest(self):
#         in_dmac = 'ee:30:ca:9d:1e:00'
#         in_smac = 'ee:cd:00:7e:70:00'
#         ip_dst_addr = '10.1.0.1'
#         ip_src_addr = '192.168.0.37'
#         ig_port = 1

#         eg_port = 2
#         out_dmac = '02:13:57:ab:cd:ef'
#         out_smac = '00:11:22:33:44:55'

#         # Before adding any table entries, the default behavior for
#         # sending in an IPv4 packet is to drop it.
#         pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
#                                    ip_dst=ip_dst_addr, ip_src = ip_src_addr,
#                                      ip_ttl=64)
#         tu.send_packet(self, ig_port, pkt)
#         tu.verify_no_other_packets(self)

#         # Add a set of table entries that the packet should match, and
#         # be forwarded out with the desired dest and source MAC
#         # addresses.
#         add_whitelist_entry_action_noaction(ip_src_addr)

#         # Check that the entry is hit, expected source and dest MAC
#         # have been written into output packet, TTL has been
#         # decremented, and that no other packets are received.
#         exp_pkt = tu.simple_tcp_packet(eth_src=out_smac, eth_dst=out_dmac,
#                                        ip_dst=ip_dst_addr, ip_src=ip_src_addr, ip_ttl=63)
#         tu.send_packet(self, ig_port, pkt)
#         tu.verify_packets(self, exp_pkt, [eg_port])