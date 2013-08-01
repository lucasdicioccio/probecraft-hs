
module Network.Probecraft.Packet.Udp (
      Udp (..)
    , UDPPort
    , udpSize
    , blankUdp
) where

import qualified Data.ByteString as B
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Word
import Data.Bits
import Control.Monad

type UDPPort = Word16

data Udp = Udp {
    udpSrcPort :: UDPPort,
    udpDstPort :: UDPPort,
    udpLength  :: Word16,
    udpChecksum :: Word16
} deriving (Show)

blankUdp = Udp noPort noPort 8 0
    where noPort = 0

instance Binary Udp where
    get = do
        sport       <- getWord16be
        dport       <- getWord16be
        len         <- getWord16be
        checksum    <- getWord16be
        return $ Udp sport dport len checksum
    put udp = do
        putWord16be $ udpSrcPort udp
        putWord16be $ udpDstPort udp
        putWord16be $ udpLength  udp
        putWord16be $ udpChecksum udp

udpSize :: Udp -> Int
udpSize _ = 16
