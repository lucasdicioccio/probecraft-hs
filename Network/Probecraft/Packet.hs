{-# LANGUAGE DeriveFunctor #-}

module Network.Probecraft.Packet (
      Packet (..)
    , payload, eth, arp, ipv4, udp, tcp, icmp
    , Layer (..)
    , (<>)
) where
import Network.Probecraft.Packet.Ethernet
import Network.Probecraft.Packet.Arp
import Network.Probecraft.Packet.Ipv4
import Network.Probecraft.Packet.Udp
import Network.Probecraft.Packet.Tcp
import Network.Probecraft.Packet.Icmp

import Data.Monoid

data Packet a = EndOfPacket
    | Payload a
    | UnexpectedTrailer a
    | EthernetLayer Ethernet    (Packet a)
    | ARPLayer      Arp         (Packet a)
    | IPv4Layer     Ipv4        (Packet a)
    | ICMPLayer     Icmp        (Packet a)
    | UDPLayer      Udp         (Packet a)
    | TCPLayer      Tcp         (Packet a)
    deriving (Show,Functor)

class Layer a where
    blank :: a
instance Layer Ethernet where
    blank = blankEthernet
instance Layer Arp where
    blank = blankArp
instance Layer Ipv4 where
    blank = blankIpv4
instance Layer Udp where
    blank = blankUdp
instance Layer Icmp where
    blank = blankIcmp
instance Layer Tcp where
    blank = blankTcp

payload = Payload

arp :: Arp -> Packet a
arp pkt = ARPLayer pkt EndOfPacket

eth :: Ethernet -> Packet a
eth pkt = EthernetLayer pkt EndOfPacket

ipv4 :: Ipv4 -> Packet a
ipv4 pkt = IPv4Layer pkt EndOfPacket

udp :: Udp -> Packet a
udp pkt = UDPLayer pkt EndOfPacket

tcp :: Tcp -> Packet a
tcp pkt = TCPLayer pkt EndOfPacket

icmp :: Icmp -> Packet a
icmp pkt = ICMPLayer pkt EndOfPacket

instance Monoid (Packet a) where
    mempty                              = EndOfPacket
    mappend EndOfPacket pkt             = pkt
    mappend pkt EndOfPacket             = pkt
    mappend (Payload a) _               = Payload a
    mappend (UnexpectedTrailer a) _     = UnexpectedTrailer a
    mappend (EthernetLayer eth _) pkt   = EthernetLayer eth pkt
    mappend (ARPLayer arp _) pkt        = ARPLayer arp pkt
    mappend (IPv4Layer v4 _) pkt        = IPv4Layer v4 pkt
    mappend (ICMPLayer icmp _) pkt      = ICMPLayer icmp pkt
    mappend (UDPLayer udp _) pkt        = UDPLayer udp pkt
    mappend (TCPLayer tcp _) pkt        = TCPLayer tcp pkt

