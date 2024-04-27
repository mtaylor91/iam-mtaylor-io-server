module IAM.Util
  ( encodePublicKey
  , encodeSecretKey
  ) where


import Crypto.Sign.Ed25519
import Data.ByteString.Base64.URL
import qualified Data.Text as T


encodePublicKey :: PublicKey -> T.Text
encodePublicKey = encodeBase64 . unPublicKey


encodeSecretKey :: SecretKey -> T.Text
encodeSecretKey = encodeBase64 . unSecretKey
