
module Network.Probecraft.Inject where
import Network.Probecraft.Packet
import Network.Probecraft.Packet.Ethernet
import Network.Probecraft.Packet.Arp
import Network.Probecraft.Packet.Ipv4
import Network.Probecraft.Packet.Udp
import Network.Probecraft.Packet.Tcp
import Network.Probecraft.Packet.Icmp
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Binary

raw :: Packet B.ByteString -> B.ByteString
raw (Payload a)                 = a
raw (EthernetLayer pkt payload) = B.concat [encode' pkt, raw payload]
raw (ARPLayer pkt payload)      = B.concat [encode' pkt, raw payload]
raw (IPv4Layer pkt payload)     = B.concat [encode' pkt, raw payload]
raw (ICMPLayer pkt payload)     = B.concat [encode' pkt, raw payload]
raw (UDPLayer pkt payload)      = B.concat [encode' pkt, raw payload]
raw (TCPLayer pkt payload)      = B.concat [encode' pkt, raw payload]
raw (EndOfPacket)               = B.empty
raw _                           = undefined

encode' :: (Binary a) => a -> B.ByteString
encode' = B.pack . L.unpack . encode
