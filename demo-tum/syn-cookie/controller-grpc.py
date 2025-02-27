import struct
import ipaddress
import p4runtime_sh.shell as sh
from asyncio import sleep

class DigestController():

    def __init__(self, sw_name, grpc_addr="0.0.0.0:9559", device_id=0):
        self.sw_name = sw_name
        self.device_id = device_id
        self.grpc_addr = grpc_addr
        p4info_txt_fname = "syn-cookie/p4src/proxy.p4info.txtpb"
        p4prog_binary_fname = "syn-cookie/p4src/proxy.json"

        # Connect to the switch using P4Runtime (gRPC)
        sh.setup(device_id=self.device_id,
                 grpc_addr=self.grpc_addr,
                 election_id=(1, 0),
                 config=sh.FwdPipeConfig(p4info_txt_fname, p4prog_binary_fname))
        print(f"Connected to {self.sw_name} via gRPC at {self.grpc_addr}")

        topology = {
            "h1": {"ip": "10.0.1.1", "mac": "00:00:0a:00:01:01", "port": 1},
            "h2": {"ip": "10.0.1.2", "mac": "00:00:0a:00:01:02", "port": 2},
            "h3": {"ip": "10.0.1.3", "mac": "00:00:0a:00:01:03", "port": 3},
        }
        # TODO add mirroring_add 100 4
        # Apply forwarding rules
        for host, info in topology.items():
            self.add_ipv4_forward_entry(info["ip"], info["mac"], info["port"])
        
        # Configure digest handling
        self.configure_digest()

    def configure_digest(self):
        """Configures the P4 digest handling for connection tracking."""
        self.digest = sh.DigestEntry("learn_connection_t")
        self.digest.max_timeout_ns = 0  # 1 second
        self.digest.max_list_size = 1
        self.digest.ack_timeout_ns = 0 # 500000000  # 0.5 second
        self.digest.insert()
        print("Configured digest: learn_connection_t")

    # Add IPv4 forwarding entries
    def add_ipv4_forward_entry(self, dst_ip, mac, port):
        te = sh.TableEntry("ipv4_lpm")(action="ipv4_forward")
        te.match["hdr.ipv4.dstAddr"] = f"{dst_ip}/32"
        te.action["dstAddr"] = mac
        te.action["port"] = str(port)
        te.insert()
        print(f"Added forwarding entry: {dst_ip} -> {mac} via port {port}")

    def recv_msg_digest(self, msg):
        print(msg)
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:32])
        offset = 17  # number of bytes in digest message
        msg = msg[32:]

        for _ in range(num):
            msg_type, arg1, arg2, arg3, arg4 = struct.unpack("!BIIII", msg[0:offset])

            if msg_type == 0:
                print("------------------------------------------------------------")
                print("This is a debug message --> action is executed successfully!")
                print(f"Message: {msg_type}, data: {arg1}, extra: {arg2}")
                print("------------------------------------------------------------")

            elif msg_type == 1:
                print(f"message type: {msg_type}, src ip: {ipaddress.IPv4Address(arg1)}, dst ip: {ipaddress.IPv4Address(arg2)}")
                self.add_whitelist_entry(arg1)

            elif msg_type == 2:
                print(f"message type: {msg_type}, connection added with Hash: {arg1}, diff: {arg2}")
                self.add_connection_entry(arg1, arg2)

                print(f"message type: {msg_type}, connection added with Hash: {arg3}, diff: {arg4}")
                self.add_connection_entry(arg3, arg4)

            else:
                print("Unknown message type!")

            msg = msg[offset:]

    def add_whitelist_entry(self, src_ip):
        """Adds an IP to the whitelist table using gRPC (P4Runtime)."""
        te = sh.TableEntry("whitelist")(action="NoAction")
        te.match["hdr.ipv4.srcAddr"] = str(ipaddress.IPv4Address(src_ip))
        te.insert()
        print(f"Added {src_ip} to whitelist.")

    def add_connection_entry(self, connection_hash, diff_value):
        """Adds a connection entry to the connections table using gRPC (P4Runtime)."""
        te = sh.TableEntry("connections")(action="saveDifferenceValue")
        te.match["meta.connectionHash"] = str(connection_hash)
        te.action["difference"] = str(diff_value)
        te.insert()
        print(f"Added connection with Hash {connection_hash} and Diff {diff_value}.")

    def run_digest_loop(self):
        """Main loop for handling digests (Replace with gRPC-based digest handling)."""
        print("Listening for digest messages via gRPC...")

        # P4Runtime handles digests internally (no nnpy needed)
        while True:
            try:
                digest_list = sh.DigestList()
                for digest_msg in digest_list.sniff():
                    print("Received Digest:", digest_msg)
                
            except Exception as e:
                print(f"Error processing digests: {e}")

def main():
    controller = DigestController("s1")
    controller.run_digest_loop()

if __name__ == "__main__":
    main()
