import struct
import p4runtime_sh.shell as sh
import p4utils.utils.sswitch_p4runtime_API as p4r


class DigestController():

    def __init__(self, sw_name, grpc_addr="0.0.0.0:9559", device_id=0):
        self.sw_name = sw_name
        self.device_id = device_id
        self.grpc_addr = grpc_addr
        p4info_txt_fname = "syn-cookie/p4src/proxy.p4info.txtpb"
        p4prog_binary_fname = "syn-cookie/p4src/proxy.json"

        # Connect to the switch using P4Runtime (gRPC)
        self.ss = p4r.SimpleSwitchP4RuntimeAPI(
            device_id=device_id,
            grpc_ip=grpc_addr[:-5],
            grpc_port=grpc_addr[-4:],
            p4rt_path=p4info_txt_fname,
            json_path=p4prog_binary_fname
        )

        print(f"Connected to {self.sw_name} via gRPC at {self.grpc_addr}")

        topology = {
            "h1": {"ip": "10.0.1.1", "mac": "00:00:0a:00:01:01", "port": 1},
            "h2": {"ip": "10.0.1.2", "mac": "00:00:0a:00:01:02", "port": 2},
            "h3": {"ip": "10.0.1.3", "mac": "00:00:0a:00:01:03", "port": 3},
        }
        # TODO add mirroring_add 100 4, do i need this, what even is it?

        for host, info in topology.items():
            self.add_ipv4_forward_entry(info["ip"], info["mac"], info["port"])

        self.configure_digest()

    def configure_digest(self):
        """Configures the P4 digest handling for connection tracking."""
        self.ss.digest_enable("learn_connection_t")
        self.ss.digest_enable("learn_debug_t")
        # print("Enabled digests:")
        # print(self.ss.digest_get_conf('learn_connection_t'))
        # print(self.ss.digest_get_conf("learn_debug_t"))

    def add_ipv4_forward_entry(self, dst_ip, mac, port):
        success = self.ss.table_add("ipv4_lpm", "ipv4_forward", [
                                    f"{dst_ip}/32"], [mac, str(port)])
        if success:
            print(f"Added entry: {dst_ip}/32 -> {mac}, Port {port}")
        else:
            print(f"Failed to add entry for {dst_ip}")

    def raw_digest_message(self, digest_msg):
        raw_data_list = []
        for data in digest_msg.data:
            struct_members = data.struct.members

            # if len(struct_members) != 5:
            #     print("Error: Digest struct does not have the expected 5 fields.")
            #     continue

            raw_data = [member.bitstring for member in struct_members]
            raw_data_list.append(raw_data)

        return raw_data_list

    def recv_msg_digest(self, msg):
        raw_data_list = self.raw_digest_message(msg)

        for raw_data in raw_data_list:
            msg_type = struct.unpack('!B', raw_data[0])[0]
            arg1 = struct.unpack('!I', b'\0\0' + raw_data[1])[0]
            arg2 = struct.unpack('!I', raw_data[2])[0]
            arg3 = struct.unpack('!I', b'\0\0' + raw_data[3])[0]
            arg4 = struct.unpack('!I', raw_data[4])[0]
            # print(f"{msg_type}, {arg1}, {arg2}, {arg3}, {arg4}")

            if msg_type == 0:
                print("------------------------------------------------------------")
                print("This is a debug message --> action is executed successfully!")
                print(f"Message: {msg_type}, data: {arg1}, extra: {arg2}")
                print("------------------------------------------------------------")

            elif msg_type == 2:
                print(
                    f"message type: {msg_type}, connection added with Hash: {arg1}, diff: {arg2}")
                self.add_connection_entry(arg1, arg2)

                print(
                    f"message type: {msg_type}, connection added with Hash: {arg3}, diff: {arg4}")
                self.add_connection_entry(arg3, arg4)

            else:
                print("Unknown message type!")

    def add_connection_entry(self, connection_hash, diff_value):
        self.ss.table_add("connections", "saveDifferenceValue", [
                          str(connection_hash)], [str(diff_value)])
        # print(
        #     f"Added connection with Hash {connection_hash} and Diff {diff_value}.")

    def run_digest_loop(self):
        print("Listening for digest messages via gRPC...")

        while True:
            try:
                message = self.ss.get_digest_list()
                if message:
                    print(f"Digest Message received: {type(message)}{message}")
                    self.recv_msg_digest(message)

            except Exception as e:
                print(f"Error processing digests: {e}")


def main():
    controller = DigestController("s1")
    controller.run_digest_loop()


if __name__ == "__main__":
    main()
