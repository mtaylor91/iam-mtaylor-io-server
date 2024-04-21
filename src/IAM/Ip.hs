module IAM.Ip
  ( module IAM.Ip
  ) where

import Data.Aeson
import Data.Textual (maybeParsed, parseText, toText)
import Network.IP.Addr
import Network.Socket
import Text.Read (readMaybe)


newtype IpAddr = IpAddr { unIpAddr :: NetAddr IP } deriving (Eq, Show)

instance ToJSON IpAddr where
  toJSON (IpAddr addr) = String $ toText addr

instance FromJSON IpAddr where
  parseJSON (String s) = case maybeParsed $ parseText s of
    Just addr -> return $ IpAddr addr
    Nothing -> fail "Invalid IP address"
  parseJSON _ = fail "Invalid IP address"

instance Read IpAddr where
  readsPrec _ s = case readMaybe s of
    Just addr -> [(IpAddr addr, "")]
    Nothing -> []


fromSockAddr :: SockAddr -> Maybe IpAddr
fromSockAddr (SockAddrInet _ addr) =
  Just $ IpAddr $ netAddr (IPv4 $ convertIpv4 addr) 32
fromSockAddr (SockAddrInet6 _ _ addr _) =
  Just $ IpAddr $ netAddr (IPv6 $ convertIpv6 addr) 128
fromSockAddr _ = Nothing


convertIpv4 :: HostAddress -> IP4
convertIpv4 addr =
  let (o0, o1, o2, o3) = hostAddressToTuple addr
   in ip4FromOctets o0 o1 o2 o3


convertIpv6 :: HostAddress6 -> IP6
convertIpv6 addr =
  let (w0, w1, w2, w3, w4, w5, w6, w7) = hostAddress6ToTuple addr
   in ip6FromWords w0 w1 w2 w3 w4 w5 w6 w7
