
module Network.Probecraft.Sniff (
      PacketMatcher
    , ethernet
    , matchUdp, matchTcp, matchIcmp, matchIpv4, matchEth, matchArp
    , (./.)
    , (.|.)
    , (.&.)
    , Disect (..)
) where

import Network.Probecraft.Packet (Packet (..))
import Network.Probecraft.Packet.Ethernet
import Network.Probecraft.Packet.Arp
import Network.Probecraft.Packet.Ipv4
import Network.Probecraft.Packet.Udp
import Network.Probecraft.Packet.Tcp
import Network.Probecraft.Packet.Icmp
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Binary
import Data.List (intersperse)
import Numeric (showHex)
import Data.Binary.Put (runPut,putWord32be)

type PacketMatcher a = Packet a -> Bool

class Disect a where
    pp :: a -> String

showFields :: [(String, String)] -> String
showFields = unlines . (map show)

hexify :: B.ByteString -> String
hexify = concat . (intersperse ":") . map (rectify . flip showHex "") . B.unpack
    where rectify s | length s == 1 = "0" ++ s
          rectify s | otherwise     = s

decimalify :: B.ByteString -> String
decimalify = concat . (intersperse ".") . (map show) . B.unpack

boolKeys :: [(String,Bool)] -> String
boolKeys = concat . (intersperse ",") . (map fst) . (filter snd)

w32tobs :: Word32 -> B.ByteString
w32tobs w = B.pack $ L.unpack $ runPut $ do putWord32be w

instance Disect Ethernet where
    pp pkt = showFields $ fields
        where fields = [("eth-destination", hexify $ ethDest pkt),
                        ("eth-source", hexify $ ethSrc pkt),
                        ("eth-protocol", show $ ethProto pkt)]

instance Disect Arp where
    pp pkt = showFields $ fields
        where fields = [("arp-hw-size", show $ arpHwSize pkt),
                        ("arp-proto-size", show $ arpProtoSize pkt),
                        ("arp-opcode", show $ arpOpCode pkt),
                        ("arp-source", hexify $ arpSrcHw pkt),
                        ("arp-target", hexify $ arpTgtHw pkt)]

instance Disect Ipv4 where
    pp pkt = showFields $ fields
        where fields = [("ip-source", decimalify $ w32tobs $ ipSrc pkt),
                        ("ip-target", decimalify $ w32tobs $ ipDst pkt),
                        ("ip-total-length", show $ ipTotalLength pkt),
                        ("ip-id", show $ ipID pkt),
                        ("ip-ttl", show $ ipTTL pkt),
                        ("ip-options", show $ ipOptions pkt)
                        ]

instance Disect Icmp where
    pp pkt = showFields $ fields
        where fields = [("icmp-kind", show $ icmpKind pkt),
                        ("icmp-code", show $ icmpCode pkt)
                        ]

instance Disect Udp where
    pp pkt = showFields $ fields
        where fields = [("udp-source-port", show $ udpSrcPort pkt),
                        ("udp-destination-port", show $ udpDstPort pkt)
                        ]

instance Disect Tcp where
    pp pkt = showFields $ fields
        where fields = [("tcp-source-port", show $ tcpSrcPort pkt),
                        ("tcp-destination-port", show $ tcpDstPort pkt),
                        ("tcp-seq", show $ tcpSeq pkt),
                        ("tcp-ack", show $ tcpAck pkt),
                        ("tcp-window", show $ tcpWindow pkt),
                        ("tcp-flags", boolKeys $ tcpFlags pkt)
                        ]

instance Disect B.ByteString where
    pp = hexify

instance (Disect a) => Disect (Packet a) where
    pp (EndOfPacket)            = ""
    pp (Payload dat)            = showFields [("payload", pp dat)]
    pp (UnexpectedTrailer dat)  = pp dat
    pp (EthernetLayer pkt x)    = pp pkt ++ pp x
    pp (ARPLayer pkt x)         = pp pkt ++ pp x
    pp (IPv4Layer pkt x)        = pp pkt ++ pp x
    pp (UDPLayer pkt x)         = pp pkt ++ pp x
    pp (TCPLayer pkt x)         = pp pkt ++ pp x
    pp (ICMPLayer pkt x)        = pp pkt ++ pp x

ethernet :: B.ByteString -> Packet B.ByteString
ethernet str = let eth = decode' $! str
                   str' = B.drop (ethSize eth) str in
        case ethProto eth of
        ARP       -> EthernetLayer eth $ arp str'
        IPv4      -> EthernetLayer eth $ ipv4 str'
        otherwise -> EthernetLayer eth $ Payload str'

arp :: B.ByteString -> Packet B.ByteString
arp str = ARPLayer (arpHead) trailer
    where arpHead = decode' str
          trailer = if 0 == B.length str'
                    then EndOfPacket
                    else (UnexpectedTrailer str')
                        where str' = B.drop (arpSize arpHead) str

ipv4 :: B.ByteString -> Packet B.ByteString
ipv4 str = IPv4Layer (ipHead) (remainder) 
          where ipHead     = decode' str
                str'       = B.drop (ipv4Size ipHead) str
                remainder  = case ipProto ipHead of
                             UDP -> udp str'
                             TCP -> tcp str'
                             ICMP -> icmp str'
                             otherwise -> Payload str'

icmp :: B.ByteString -> Packet B.ByteString
icmp str = ICMPLayer (icmpHead) (remainder)
    where icmpHead  = decode' str
          str'      = B.drop (icmpSize icmpHead) str
          remainder = Payload str'

udp :: B.ByteString -> Packet B.ByteString
udp str = UDPLayer (udpHead) (remainder)
    where udpHead   = decode' str
          str'      = B.drop (udpSize udpHead) str
          remainder = Payload str'

tcp :: B.ByteString -> Packet B.ByteString
tcp str = TCPLayer (tcpHead) (remainder)
    where tcpHead   = decode' str
          str'      = B.drop (tcpSize tcpHead) str
          remainder = Payload str'

decode' :: (Binary a) => B.ByteString -> a
decode' = decode . L.pack . B.unpack

matchUdp :: PacketMatcher a
matchUdp (UDPLayer a _) = True
matchUdp _              = False

matchTcp :: PacketMatcher a
matchTcp (TCPLayer a _) = True
matchTcp _              = False

matchIcmp :: PacketMatcher a
matchIcmp (ICMPLayer a _) = True
matchIcmp _               = False

matchIpv4 :: PacketMatcher a
matchIpv4 (IPv4Layer a _) = True
matchIpv4 _               = False

matchArp :: PacketMatcher a
matchArp (ARPLayer a _) = True
matchArp _               = False

matchEth :: PacketMatcher a
matchEth (EthernetLayer a _) = True
matchEth _                   = False

packetPayload :: Packet a -> Maybe (Packet a)
packetPayload (EthernetLayer _ dat) = Just dat
packetPayload (ARPLayer _ dat)      = Just dat
packetPayload (IPv4Layer _ dat)     = Just dat
packetPayload (ICMPLayer _ dat)     = Just dat
packetPayload (UDPLayer _ dat)      = Just dat
packetPayload (TCPLayer _ dat)      = Just dat
packetPayload _                     = Nothing

-- combines two matchers at different layers
(./.) :: PacketMatcher a -> PacketMatcher a -> PacketMatcher a
m1 ./. m2 = \pkt -> if (m1 pkt)
                    then maybe False m2 (packetPayload pkt)
                    else False

-- combines two matchers with a logical OR
(.|.) :: PacketMatcher a -> PacketMatcher a -> PacketMatcher a
m1 .|. m2 = \pkt -> m1 pkt || m2 pkt

-- combines two matchers with a logical AND
(.&.) :: PacketMatcher a -> PacketMatcher a -> PacketMatcher a
m1 .&. m2 = \pkt -> m1 pkt && m2 pkt
