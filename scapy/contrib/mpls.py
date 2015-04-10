# http://trac.secdev.org/scapy/ticket/31 

# scapy.contrib.description = MPLS
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

class MPLS(Packet): 
   name = "MPLS" 
   fields_desc =  [ BitField("label", 3, 20), 
                    BitField("cos", 0, 3), 
                    BitField("s", 1, 1), 
                    ByteField("ttl", 0)  ] 

   def guess_payload_class(self, payload):
       if self.label in (0, 3):
           return IP
       elif self.label == 2:
           return IPv6
       else:
           first_byte = ord(str(payload)[0])
           if first_byte >= 0x45 and first_byte <= 0x4f:
               return IP
           elif first_byte >= 0x60 and first_byte <= 0x6f:
               return IPv6
           else:
               return self.default_payload_class(payload)

bind_layers(Ether, MPLS, type=0x8847)
