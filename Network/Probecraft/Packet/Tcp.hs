
module Network.Probecraft.Packet.Tcp (
      Tcp (..)
    , TCPPort
    , TCPFlags
    , tcpFlags
    , TCPOption
    , blankTcp
    , tcpSize
) where

import qualified Data.ByteString as B
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Word
import Data.Bits
import Control.Monad

type TCPPort        = Word16
type TCPFlags       = [(String,Bool)]
type TCPOption      = B.ByteString

data Tcp = Tcp {
    tcpSrcPort      :: TCPPort,
    tcpDstPort      :: TCPPort,
    tcpSeq          :: Word32,
    tcpAck          :: Word32,
    tcpHeaderLength :: Word8,
    tcpFlagsValue   :: Word8,
    tcpWindow       :: Word16,
    tcpChecksum     :: Word16,
    tcpUrgentPtr    :: Word16,
    tcpOptions      :: [TCPOption],
    tcpStuffing     :: Maybe B.ByteString
} deriving (Show)

blankTcp = Tcp noPort noPort 0 0 20 0 0 0 0 [] Nothing
    where noPort = 0

instance Binary Tcp where
    get = do
        sport       <- getWord16be
        dport       <- getWord16be
        seq         <- getWord32be
        ack         <- getWord32be
        headLen     <- getWord8
        flagsVal    <- getWord8
        window      <- getWord16be
        checksum    <- getWord16be
        urg         <- getWord16be
        return $ Tcp sport dport seq ack headLen flagsVal window checksum urg [] Nothing
    put tcp = do
        putWord16be $ tcpSrcPort tcp
        putWord16be $ tcpDstPort tcp
        putWord32be $ tcpSeq tcp
        putWord32be $ tcpAck tcp
        putWord8    $ tcpHeaderLength tcp
        putWord8    $ tcpFlagsValue tcp
        putWord16be $ tcpWindow tcp
        putWord16be $ tcpChecksum tcp
        putWord16be $ tcpUrgentPtr tcp

tcpSize :: Tcp -> Int
tcpSize pkt = fromIntegral $ (tcpHeaderLength pkt .&. 0xf0) `shift` 2

tcpFlags :: Tcp -> TCPFlags
tcpFlags pkt = [("CWR",cwr),("ECN",ecn),("URG",urg),
    ("ACK",ack),("PUSH",push),("RST",rst),("SYN",syn),("FIN",fin)]
    where flags = tcpFlagsValue pkt
          cwr  = testBit flags 7
          ecn  = testBit flags 6
          urg  = testBit flags 5
          ack  = testBit flags 4
          push = testBit flags 3
          rst  = testBit flags 2
          syn  = testBit flags 1
          fin  = testBit flags 0
