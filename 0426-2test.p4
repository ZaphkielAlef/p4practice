#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;

/* H E A D E R S  */

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header virtual_ip_t {
    bit<32> addr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

/* P A R S E R */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/* C H E C K    S U M */
/* 目前沒驗證 */

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/* I N G R E S S */

table ip_mapping_table {
    reads {
        ipv4_t.dstAddr: exact;
    }
    writes {
        ipv4_t.dstAddr;
    }
}

control ip_hopping_control {
    counter timer;
    table ip_mapping_table mapping_table;

    apply {
        timer.set(60);
        mapping_table.add(192.168.1.10, 10.0.0.1);
    }

    apply(timer) {
        mapping_table.delete(192.168.1.10);

        if (mapping_table.lookup(10.0.0.1)) {
            mapping_table.modify(192.168.1.10, 10.0.0.1);
            
        } else {
            mapping_table.modify(192.168.1.11, 10.0.0.1);
        }
         timer.reset();
    }
}

control ingress {
    apply(ip_hopping_control);
    apply(ip_mapping_table);

    if (ip_mapping_table.lookup(hit)) {
        ipv4.dstAddr = ip_mapping_table.apply().ipv4.dstAddr;
    }
    standard_metadata.egress_spec = get_egress_port(ipv4.dstAddr);
    apply(standard_metadata.egress_spec);
}



control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) { 
            ipv4_lpm.apply(); 
        }
    }
}

/* EGRESS */
control egress {
    apply(ip_mapping_table);

    if (ip_mapping_table.lookup(hit)) {
        ipv4.dstAddr = ip_mapping_table.apply().ipv4.dstAddr;
    }
    apply();
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/* CHECKSUM COMPUTATION */

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/* DEPARSER */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}


V1Switch(
MyParser(),
MyVerifyChecksum(),
ingress(),
MyIngress(),
MyEgress(),
egress(),
MyComputeChecksum(),
MyDeparser()
) main;
