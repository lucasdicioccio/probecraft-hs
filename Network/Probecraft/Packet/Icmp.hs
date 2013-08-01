
module Network.Probecraft.Packet.Icmp (
      Icmp (..)
    , ICMPCode
    , ICMPKind (..)
    , blankIcmp
    , icmpSize
) where

import qualified Data.ByteString as B
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Word
import Data.Bits
import Control.Monad

type ICMPCode = Word8
data ICMPKind = Unknown Word8 | EchoReply | DestinationUnreachable | SourceQuench | 
    Redirect | EchoRequest | TimeExceeded | ParameterProblems | 
    TimestampRequest | TimestampReply | InformationRequest | InformationReply 
    deriving  (Show)

data Icmp = Icmp {
    icmpKind :: ICMPKind,
    icmpCode :: ICMPCode,
    icmpChecksum :: Word16,
    icmpOptionalField :: Word32
} deriving (Show)

blankIcmp = Icmp noKind 0 0 0
    where noKind = Unknown 0

instance Binary Icmp where
    get = do
        kind        <- getWord8
        code        <- getWord8
        checksum    <- getWord16be
        opt         <- getWord32be
        return $ Icmp (parseKind kind) code checksum opt
    put icmp = do
        putWord8 $ unparseKind $ icmpKind icmp
        putWord8 $ icmpCode icmp
        putWord16be $ icmpChecksum icmp
        putWord32be $ icmpOptionalField icmp

parseKind :: Word8 -> ICMPKind
parseKind 0 = EchoReply
parseKind 3 = DestinationUnreachable
parseKind 4 = SourceQuench
parseKind 5 = Redirect
parseKind 8 = EchoRequest
parseKind 11 = TimeExceeded
parseKind 12 = ParameterProblems
parseKind 13 = TimestampRequest
parseKind 14 = TimestampReply
parseKind 15 = InformationRequest
parseKind 16 = InformationReply
parseKind x = Unknown x

unparseKind :: ICMPKind -> Word8
unparseKind EchoReply = 0
unparseKind DestinationUnreachable = 3
unparseKind SourceQuench = 4
unparseKind Redirect = 5
unparseKind EchoRequest = 8
unparseKind TimeExceeded = 11
unparseKind ParameterProblems = 12
unparseKind TimestampRequest = 13
unparseKind TimestampReply = 14
unparseKind InformationRequest = 15
unparseKind InformationReply = 16
unparseKind (Unknown x) = x

icmpSize :: Icmp -> Int
icmpSize _ = 8
