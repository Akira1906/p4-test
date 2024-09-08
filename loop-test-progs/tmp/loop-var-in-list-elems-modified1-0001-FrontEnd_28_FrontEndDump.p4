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
    bit<8> n;
    bit<8> m;
    bit<8> p;
    bit<8> q;
    apply {
        n = 8w0;
        m = 8w4;
        p = 8w8;
        q = 8w16;
        for (bit<8> i in (list<bit<8>>){8w1,8w2,m,p,q}) {
            n = n + i;
            m = 8w32;
            p = 8w64;
            q = 8w128;
        }
        hdr.ethernet.srcAddr[7:0] = n;
        hdr.ethernet.srcAddr[15:8] = m;
        hdr.ethernet.srcAddr[23:16] = p;
        hdr.ethernet.srcAddr[31:24] = q;
        stdmeta.egress_spec = 9w1;
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
