{-# LANGUAGE OverloadedStrings #-}
module Lib.Keypair (generateKeypair) where

import Crypto.Sign.Ed25519
import Data.Aeson
import Data.ByteString.Base64
import Data.ByteString.Lazy (toStrict)
import Data.Text.Encoding
import qualified Data.Text as T


data Keypair = Keypair
  { publicKey :: !PublicKey
  , secretKey :: !SecretKey
  } deriving (Eq, Show)

instance FromJSON Keypair where
  parseJSON (Object obj) = do
    pkBase64 <- obj .: "publicKey"
    skBase64 <- obj .: "secretKey"
    case (decodeBase64 $ encodeUtf8 pkBase64, decodeBase64 $ encodeUtf8 skBase64) of
      (Right pk, Right sk) -> return $ Keypair (PublicKey pk) (SecretKey sk)
      (_, _) -> fail "Invalid base64 encoding"
  parseJSON _ = fail "Invalid JSON object"

instance ToJSON Keypair where
  toJSON (Keypair pk sk) = object
    [ "publicKey" .= encodeBase64 (unPublicKey pk)
    , "secretKey" .= encodeBase64 (unSecretKey sk)
    ]


generateKeypair :: IO ()
generateKeypair = do
  (pk, sk) <- createKeypair
  let keypair = Keypair pk sk
  putStrLn $ T.unpack $ decodeUtf8 $ toStrict $ encode $ toJSON keypair
  return ()
