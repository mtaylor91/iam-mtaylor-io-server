{-# LANGUAGE OverloadedStrings #-}
module IAM.UserPublicKey
  ( module IAM.UserPublicKey
  ) where

import Crypto.Sign.Ed25519
import Data.Aeson
import Data.ByteString.Base64.URL
import Data.Text
import Data.Text.Encoding


data UserPublicKey = UserPublicKey
  { userPublicKey :: !PublicKey
  , userPublicKeyDescription :: !Text
  } deriving (Eq, Show)


instance FromJSON UserPublicKey where
  parseJSON (Object obj) = do
    key <- obj .: "key"
    description <- obj .: "description"
    case decodeBase64 $ encodeUtf8 key of
      Left _ -> fail "Invalid JSON"
      Right bs -> return $ UserPublicKey (PublicKey bs) description
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserPublicKey where
  toJSON (UserPublicKey key description) = object
    [ "description" .= description
    , "key" .= encodeBase64 (unPublicKey key)
    ]
