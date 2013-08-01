
module Network.Probecraft.Packet.Arp (
      Arp (..)
    , arpSize
    , MACAddress
    , HardwareType (..)
    , ProtoType (..)
    , OpCode (..)
    , blankArp
) where

import qualified Data.ByteString as B
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import Control.Monad
import Network.Probecraft.Utils

type MACAddress     = B.ByteString
data HardwareType   = EthernetHw | UnknownHarwareType Word16 deriving (Show,Eq)
data ProtoType      = IPv4Proto | UnknownProtoType Word16 deriving (Show,Eq)
data OpCode         = Request | Reply | UnknownOpCode Word16 deriving (Show,Eq)

data Arp = Arp {
    arpHwType       :: HardwareType,
    arpProtoType    :: ProtoType,
    arpHwSize       :: Int,
    arpProtoSize    :: Int,
    arpOpCode       :: OpCode,
    arpSrcHw        :: MACAddress,
    arpSrcProto     :: B.ByteString,
    arpTgtHw        :: MACAddress,
    arpTgtProto     :: B.ByteString
} deriving (Show)

blankArp = Arp noType noProto 6 4 noCode noAddrHw noAddrProto noAddrHw noAddrProto
    where noType    = UnknownHarwareType 0
          noProto   = UnknownProtoType 0
          noCode    = UnknownOpCode 0
          noAddrHw      = unhexify "00:00:00:00:00:00"
          noAddrProto   = undecimalify "0.0.0.0"

arpSize :: Arp -> Int
arpSize arp = 8 + 2*(arpHwSize arp + arpProtoSize arp)

instance Binary Arp where
    get = do 
        hwType    <- getWord16be
        protoType <- getWord16be
        hwSize    <- getWord8 >>= return . fromIntegral
        protoSize <- getWord8 >>= return . fromIntegral
        opCode    <- getWord16be
        srcHw     <- getByteString hwSize
        srcProto  <- getByteString protoSize
        tgtHw     <- getByteString hwSize
        tgtProto  <- getByteString protoSize
        return $ Arp (parseHardwareType hwType) (parseProtoType protoType) hwSize protoSize 
            (parseOpCode opCode)
            srcHw srcProto tgtHw tgtProto
    put arp = do
        putWord16be $ unparseHardwareType $ arpHwType arp
        putWord16be $ unparseProtoType $ arpProtoType arp
        putWord8 $ fromIntegral $ arpHwSize arp
        putWord8 $ fromIntegral $ arpProtoSize arp
        putWord16be $ unparseOpCode $ arpOpCode arp
        putByteString $ arpSrcHw arp
        putByteString $ arpSrcProto arp
        putByteString $ arpTgtHw arp
        putByteString $ arpTgtProto arp

parseHardwareType :: Word16 -> HardwareType
parseHardwareType 1 = EthernetHw
parseHardwareType x = UnknownHarwareType x

unparseHardwareType :: HardwareType -> Word16
unparseHardwareType EthernetHw              = 1
unparseHardwareType (UnknownHarwareType x)  = x

parseProtoType :: Word16 -> ProtoType
parseProtoType 0x800 = IPv4Proto
parseProtoType x     = UnknownProtoType x

unparseProtoType :: ProtoType -> Word16
unparseProtoType IPv4Proto             = 0x800
unparseProtoType (UnknownProtoType x)  = x

parseOpCode :: Word16 -> OpCode
parseOpCode 1 = Request
parseOpCode 2 = Reply
parseOpCode x = UnknownOpCode x

unparseOpCode :: OpCode -> Word16
unparseOpCode Request           = 1
unparseOpCode Reply             = 2
unparseOpCode (UnknownOpCode x) = x
