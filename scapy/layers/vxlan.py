"""
Virtual eXtensible Local Area Network (VXLAN)

http://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-08
"""

from scapy.packet import Packet, bind_layers
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.fields import BitField, XBitField, FlagsField

class VXLAN(Packet):
    name = 'VXLAN'

    fields_desc = [
        FlagsField('flags', default=1 << 3, size=8,
                   names=['R', 'R', 'R', 'R', 'I', 'R', 'R', 'R']),
        XBitField('reserved1', default=0x000000, size=24),
        BitField('vni', None, size=24),
        XBitField('reserved2', default=0x00, size=8),
    ]

    overload_fields = {
        UDP: {'dport': 4789},
    }

    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)
bind_layers(VXLAN, Ether)
