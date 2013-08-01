
module Network.Probecraft.Packet.Ipv4 (
      IPOption (..)
    , IPOptionField (..)
    , IPAddress
    , IPFlags
    , Stuffing
    , IPProtocol (..)
    , Ipv4 (..)
    , blankIpv4
    , ipv4Size
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Word
import Data.Bits
import Control.Monad

type IPAddress     = Word32
type IPFlags       = [(String,Bool)]
type Stuffing      = Maybe B.ByteString

data IPOptionField = RawData B.ByteString | Options [IPOption] deriving (Show)

data IPOption      = IPOption { 
    ipOptionType   :: Word8,
    ipOptionLength :: Maybe Word8,
    ipOptionData   :: Maybe B.ByteString
} deriving (Show,Eq)

data IPOptionType = EndOfOptionList | NoOperation | Security 
    | LooseSourceRouting | InternetTimestamp | RecordRoute 
    | StreamID | StrictSourceRouting | UnknownOptionType Word8 
    deriving (Show,Eq)

data IPProtocol    = TCP | UDP | ICMP | UnknownIPProtocol Word8 deriving (Show)

instance Binary IPOption where
    get = do
        t <- getWord8
        case parseIpOptionType t of
            NoOperation     -> endOfPacket t
            EndOfOptionList -> endOfPacket t
            otherwise       -> continuePacket t
            where endOfPacket x = return $ IPOption x Nothing Nothing
                  continuePacket t = do
                        l <- getWord8
                        dat <- getByteString $ (fromIntegral l) - 2
                        return $ IPOption t (Just l) (Just dat)

    put opt = do
        putWord8 $ ipOptionType opt
        maybe (return ()) (putWord8) $ ipOptionLength opt
        maybe (return ()) (putByteString) $ ipOptionData opt

data Ipv4 = Ipv4 {
    ipVersionHeaderLength :: Word8,
    ipServices            :: Word8,
    ipTotalLength         :: Word16,
    ipID                  :: Word16,
    ipFlagsOffset         :: Word16,
    ipTTL                 :: Word8,
    ipProto               :: IPProtocol,
    ipChksum              :: Word16,
    ipSrc                 :: IPAddress,
    ipDst                 :: IPAddress,
    ipOptions             :: IPOptionField,
    ipStuffing            :: Stuffing
} deriving (Show)

blankIpv4 = Ipv4 0 0 20 0 0 255 noProto 0 noAddr noAddr noOpt noStuffing
    where noProto = UnknownIPProtocol 0
          noAddr  = 0
          noOpt   = Options []
          noStuffing = Nothing 

instance Binary Ipv4 where
    get = do
        versionHeadlen <- getWord8
        services       <- getWord8
        totalLength    <- getWord16be
        identifier     <- getWord16be
        flagsOffset    <- getWord16be
        ttl            <- getWord8
        proto          <- getWord8
        checksum       <- getWord16be
        src            <- getWord32be
        dst            <- getWord32be
        let remainingLength = (ipv4Size' versionHeadlen) - 20
        optData        <- getByteString remainingLength
        return $ Ipv4 versionHeadlen services totalLength identifier flagsOffset ttl
            (parseProto proto) checksum src dst (Options $ parseOptions remainingLength optData) Nothing

    put ipv4 = do
        putWord8 $ ipVersionHeaderLength ipv4
        putWord8 $ ipServices ipv4
        putWord16be $ ipTotalLength ipv4
        putWord16be $ ipID ipv4
        putWord16be $ ipFlagsOffset ipv4
        putWord8 $ ipTTL ipv4
        putWord8 $ unparseProto $ ipProto ipv4
        putWord16be $ ipChksum ipv4
        putWord32be $ ipSrc ipv4
        putWord32be $ ipDst ipv4
        let optField  = ipOptions ipv4
        case optField of
            RawData x -> putByteString x
            Options opts -> do  putByteString optData
                                maybe (return ()) (putByteString) $ ipStuffing ipv4
                                where (optData,stuffing) = unparseOptions opts

parseIpOptionType :: Word8 -> IPOptionType
parseIpOptionType x = parseIpOptionType' (x .&. 0x1f)
    where parseIpOptionType' 0 = EndOfOptionList
          parseIpOptionType' 1 = NoOperation
          parseIpOptionType' 2 = Security
          parseIpOptionType' 3 = LooseSourceRouting
          parseIpOptionType' 4 = InternetTimestamp
          parseIpOptionType' 7 = RecordRoute
          parseIpOptionType' 8 = StreamID
          parseIpOptionType' 9 = StrictSourceRouting
          parseIpOptionType' x = UnknownOptionType x

unparseOptions :: [IPOption] -> (B.ByteString,Stuffing)
unparseOptions xs = (str,stuff)
    where str   = B.concat $ map (B.pack . L.unpack . encode) xs
          stuff = case B.length str `rem` 4 of 
                    0 -> Nothing
                    x -> Just $ B.pack $ replicate x 0

parseOptions :: Int -> B.ByteString -> [IPOption]
parseOptions len str 
    | len == 0           = []
    | len < B.length str = []
    | otherwise          = o:opts where
        o     = decode . L.pack . B.unpack $ str
        opts  = case (parseIpOptionType $ ipOptionType o) of
                    EndOfOptionList -> []
                    otherwise       -> parseOptions len' str'
                where len' = len - (maybe 1 (fromIntegral) $ ipOptionLength o)
                      str' = B.drop len' str

parseProto :: Word8 -> IPProtocol
parseProto 6    = TCP
parseProto 17   = UDP
parseProto 1    = ICMP
parseProto x    = UnknownIPProtocol x

unparseProto :: IPProtocol -> Word8
unparseProto TCP = 6
unparseProto UDP = 17 
unparseProto ICMP = 1
unparseProto (UnknownIPProtocol x) = x

ipVersion :: Ipv4 -> Int
ipVersion pkt = fromIntegral $ ((ipVersionHeaderLength pkt) .&. 0xf0) `shift` (-4)

ipv4Size :: Ipv4 -> Int
ipv4Size pkt = ipv4Size' $ ipVersionHeaderLength pkt

ipv4Size' :: Word8 -> Int
ipv4Size' w8 = fromIntegral $ (w8 .&. 0x0f)  `shift` 2

ipFlags :: Ipv4 -> IPFlags
ipFlags pkt = [("more-fragments",mf),("dont-fragment",df),("reserved",reserved)]
    where flags = ipFlagsOffset pkt
          mf = testBit flags 13
          df = testBit flags 14
          reserved = testBit flags 15

ipOffset :: Ipv4 -> Int
ipOffset pkt = fromIntegral $ ((ipFlagsOffset pkt) .&. 0x1fff)
