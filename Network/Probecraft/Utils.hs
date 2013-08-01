
module Network.Probecraft.Utils where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Numeric (readHex,readDec)
import Data.List.Split (splitOn)
import Data.Word

unhexify :: String -> B.ByteString
unhexify = unhexify' ":"

unhexify' :: String -> String -> B.ByteString
unhexify' sep str = splitReadStr readHex sep str

undecimalify :: String -> B.ByteString
undecimalify = undecimalify' "."

undecimalify' :: String -> String -> B.ByteString
undecimalify' sep str = splitReadStr readDec sep str

splitReadStr :: Eq a => ([a] -> [(Word8, b)]) -> [a] -> [a] -> B.ByteString
splitReadStr f sep str = B.pack $ concatMap (map fst . f) $ (splitOn sep) str
