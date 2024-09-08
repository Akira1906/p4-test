#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct metadata_t {
}

struct headers_t {
    ethernet_t ethernet;
}

parser parserImpl(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t stdmeta) {
    state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition accept;
    }
}

control ingressImpl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t stdmeta) {
    bit<8> n = hdr.ethernet.srcAddr[15:8];
    bit<8> i;
    apply {
        bit<8> k1 = n + 8w1;
        bit<8> j1 = n + 8w8;
        {
            bit<8> k2 = n + 8w1;
            bit<8> n = n + 8w5;
            bit<8> j2 = n + 8w3;
            if (k1 != k2) {
                hdr.ethernet.dstAddr[47:47] = 1w1;
            } else {
                hdr.ethernet.dstAddr[47:47] = 1w0;
            }
            if (j1 != j2) {
                hdr.ethernet.dstAddr[46:46] = 1w1;
            } else {
                hdr.ethernet.dstAddr[46:46] = 1w0;
            }
            if (n != k2) {
                hdr.ethernet.dstAddr[45:45] = 1w1;
            } else {
                hdr.ethernet.dstAddr[45:45] = 1w0;
            }
            hdr.ethernet.srcAddr[23:16] = k2;
            hdr.ethernet.srcAddr[15:8] = n;
            hdr.ethernet.srcAddr[7:0] = j2;
            stdmeta.egress_spec = 9w1;
        }
    }
}

control egressImpl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t stdmeta) {
    apply {
    }
}

control deparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
    }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
    }
}

control updateChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
    }
}

V1Switch<headers_t, metadata_t>(parserImpl(), verifyChecksum(), ingressImpl(), egressImpl(), updateChecksum(), deparserImpl()) main;
