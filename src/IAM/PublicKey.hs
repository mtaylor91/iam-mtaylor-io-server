{-# LANGUAGE OverloadedStrings #-}
module IAM.PublicKey
  ( PublicKey'(..)
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.ByteString.Base64.URL (decodeBase64, encodeBase64)
import Data.Text.Encoding (encodeUtf8)
import Servant (FromHttpApiData(..), ToHttpApiData(..))


newtype PublicKey' = PublicKey' { unPublicKey' :: PublicKey }


instance FromHttpApiData PublicKey' where
  parseUrlPiece s =
    case decodeBase64 $ encodeUtf8 s of
      Right pk -> Right $ PublicKey' $ PublicKey pk
      Left _ -> Left "Invalid public key"


instance ToHttpApiData PublicKey' where
  toUrlPiece (PublicKey' (PublicKey pk)) = encodeBase64 pk
