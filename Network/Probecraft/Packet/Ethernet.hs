
module Network.Probecraft.Packet.Ethernet (
      Ethernet (..)
    , MACAddress
    , EthProtocol (..)
    , blankEthernet
    , ethSize
) where

import qualified Data.ByteString as B
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Word
import Control.Monad
import Network.Probecraft.Utils

type MACAddress     = B.ByteString
data EthProtocol    = IPv4 | ARP | UnknownProto Word16 deriving (Show)
data Ethernet       = Ethernet {
      ethDest  :: MACAddress
    , ethSrc   :: MACAddress
    , ethProto :: EthProtocol
} deriving (Show)

blankEthernet :: Ethernet
blankEthernet = Ethernet noAddr noAddr noProto
    where noAddr    = unhexify "00:00:00:00:00:00"
          noProto   = UnknownProto 0

ethSize :: Ethernet -> Int
ethSize _ = 14

instance Binary Ethernet where
    get = do 
        dst <- getByteString 6
        src <- getByteString 6
        proto <- getWord16be
        return $ Ethernet dst src (parseProto proto)
    put eth = do
        putByteString $ ethDest eth
        putByteString $ ethSrc eth
        putWord16be $ unparseProto $ ethProto eth

parseProto :: Word16 -> EthProtocol
parseProto 0x800 = IPv4
parseProto 0x806 = ARP
parseProto x     = UnknownProto x

unparseProto :: EthProtocol -> Word16
unparseProto IPv4         = 0x800
unparseProto ARP          = 0x806 
unparseProto (UnknownProto x)  = 0
