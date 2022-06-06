#!/usr/bin/env python3

import socket
from scapy.all import srp1
from scapy.all import Packet
from scapy.all import Ether, IP, ByteField, IntField
from scapy.all import bind_layers

class Mem(Packet):
    name = "Mem"
    fields_desc = [
        ByteField("op_err", 0),
        IntField("index", 0),
        IntField("value", 0),
        IntField("lock", 0),
        ]


bind_layers(IP, Mem, proto=0xFD)

class CellIndexError(Exception):
    pass

class LockError(Exception):
    pass

class NetworkMemory:
    def __init__(self,cell,source_ip,target_ip,password):
        self.cell = cell
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.password = password


    def lock(self):
        while True:
            mem = srp1(Ether(dst='00:04:00:00:00:00') / IP(src=self.source_ip, dst=self.target_ip) / Mem(op_err=0, index=self.cell, lock=self.password), iface='eth0', verbose=False)[Mem]
            value = mem.value
            err = mem.op_err
            if err == 2:
                raise CellIndexError("Wrong index!")
            elif err == 0:
                return value


    def unlock(self):
        mem = srp1(Ether(dst='00:04:00:00:00:00') / IP(src=self.source_ip, dst=self.target_ip) / Mem(op_err=1, index=self.cell, lock=self.password), iface='eth0', verbose=False)[Mem]
        err = mem.op_err
        if err == 2:
            raise CellIndexError("Wrong index!")
        elif err == 1:
            raise LockError("Wrong cell state!")

    def unlocked_write(self, value):
        while True:
            mem = srp1(Ether(dst='00:04:00:00:00:00') / IP(src=self.source_ip, dst=self.target_ip) / Mem(op_err=2, index=self.cell, value=value, lock=0), iface='eth0', verbose=False)[Mem]
            err = mem.op_err
            if err == 2:
                raise CellIndexError("Wrong index!")
            elif err == 0:
                break

    def locked_write(self, value):
        mem = srp1(Ether(dst='00:04:00:00:00:00') / IP(src=self.source_ip, dst=self.target_ip) / Mem(op_err=2, index=self.cell, value=value, lock=self.password), iface='eth0', verbose=False)[Mem]
        err = mem.op_err
        if err == 2:
            raise CellIndexError("Wrong index!")
        elif err == 1:
            raise LockError("Wrong cell state!")

    def unlocked_read(self):
        while True:
            mem = srp1(Ether(dst='00:04:00:00:00:00') / IP(src=self.source_ip, dst=self.target_ip) / Mem(op_err=3, index=self.cell, lock=0), iface='eth0', verbose=False)[Mem]
            err = mem.op_err
            value = mem.value
            if err == 2:
                raise CellIndexError("Wrong index!")
            elif err == 0:
                return value

    def locked_read(self):
        mem = srp1(Ether(dst='00:04:00:00:00:00') / IP(src=self.source_ip, dst=self.target_ip) / Mem(op_err=3, index=self.cell, lock=self.password), iface='eth0', verbose=False)[Mem]
        err = mem.op_err
        value = mem.value
        if err == 2:
            raise CellIndexError("Wrong index!")
        elif err == 1:
            raise LockError("Wrong cell state!")
        elif err == 0:
            return value

    def read_write(self, f):
        x = self.lock()
        x = f(x)
        self.locked_write(x)
        self.unlock()
