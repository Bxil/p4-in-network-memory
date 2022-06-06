/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> cell_t;
typedef bit<8>  op_err_t;

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROT_MEM  = 0xFD;

const op_err_t MEMOP_LOCK = 0;
const op_err_t MEMOP_UNLOCK = 1;
const op_err_t MEMOP_WRITE = 2;
const op_err_t MEMOP_READ = 3;

const op_err_t MEMERR_OK = 0;
const op_err_t MEMERR_LOCK = 1;
const op_err_t MEMERR_INDEX = 2;

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

header mem_t {
	op_err_t op_err;
	bit<32> index;
	cell_t value;
	bit<32> lock;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
	mem_t        mem;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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
        transition select(hdr.ipv4.protocol) {
            PROT_MEM: parse_mem;
            default: accept;
        }
    }

	state parse_mem {
		packet.extract(hdr.mem);
		transition accept;
	}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

#define CELLS 1024
    register<bit<32>>(CELLS) locks;
    register<cell_t>(CELLS) cells;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action memory() {

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

    table memory_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            memory;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    apply {
        if (hdr.mem.isValid()) {
            switch (memory_exact.apply().action_run) {
                memory: {
                    op_err_t op = hdr.mem.op_err;
                    if (hdr.mem.index >= CELLS) {
                        hdr.mem.op_err = MEMERR_INDEX;
                    } else @atomic {
                        hdr.mem.op_err = MEMERR_OK;
                        bit<32> lockValue;
                        locks.read(lockValue, hdr.mem.index);
                        if (op == MEMOP_LOCK && lockValue == 0) {
                            locks.write(hdr.mem.index, hdr.mem.lock);
                            cells.read(hdr.mem.value, hdr.mem.index);
                        } else if (op == MEMOP_UNLOCK && lockValue == hdr.mem.lock) {
                            locks.write(hdr.mem.index, 0);
                            hdr.mem.lock = 0;
                            cells.read(hdr.mem.value, hdr.mem.index);
                        } else if (op == MEMOP_WRITE && lockValue == hdr.mem.lock) {
                            cells.write(hdr.mem.index, hdr.mem.value);
                        } else if (op == MEMOP_READ && lockValue == hdr.mem.lock) {
                            cells.read(hdr.mem.value, hdr.mem.index);
                        } else {
                            hdr.mem.op_err = MEMERR_LOCK;
                        }
                    }

                    ip4Addr_t tmp = hdr.ipv4.dstAddr;
                    hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
                    hdr.ipv4.srcAddr = tmp;
                }
            }
        }

        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
		packet.emit(hdr.mem);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
