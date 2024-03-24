{-# LANGUAGE OverloadedStrings #-}
module IAM.Client.Auth
  ( clientAuthInfo
  , ClientAuth(..)
  ) where

import Control.Exception
import Crypto.Sign.Ed25519
import Data.ByteString hiding (pack, unpack)
import Data.ByteString.Base64
import Data.CaseInsensitive
import Data.Text
import Data.Text.Encoding
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Client

import IAM.Config (configEmail, configSecretKey, headerPrefix)


newtype ClientAuth = ClientAuth { clientAuth :: Request -> IO Request }


clientAuthInfo :: IO ClientAuth
clientAuthInfo = do
  email <- configEmail
  secretKey <- configSecretKey
  case decodeSecretKey $ pack secretKey of
    Nothing ->
      throw $ userError "Invalid secret key"
    Just secretKey' ->
      return $ mkClientAuth email secretKey'


mkClientAuth :: String -> SecretKey -> ClientAuth
mkClientAuth email secretKey = ClientAuth $ \req -> do
  case lookup "Authorization" $ requestHeaders req of
    Just _ -> return req
    Nothing -> do
      requestId <- nextRandom
      let publicKey = encodePublicKey secretKey
          authorization = authHeader reqStringToSign secretKey
          reqStringToSign = authStringToSign req requestId
      return $ req
        { requestHeaders = requestHeaders req
          ++ [ ("Authorization", authorization)
             , (headerPrefix' <> "-User-Id", encodeUtf8 $ pack email)
             , (headerPrefix' <> "-Public-Key", encodeUtf8 publicKey)
             , (headerPrefix' <> "-Request-Id", encodeUtf8 $ pack $ toString requestId)
             ]
        }
  where headerPrefix' = mk (encodeUtf8 $ pack headerPrefix)


encodePublicKey :: SecretKey -> Text
encodePublicKey = encodeBase64 . unPublicKey . toPublicKey


decodeSecretKey :: Text -> Maybe SecretKey
decodeSecretKey t =
  case decodeBase64 (encodeUtf8 t) of
    Left _ -> Nothing
    Right bs -> Just $ SecretKey bs


authHeader :: Text -> SecretKey -> ByteString
authHeader reqStringToSign secretKey = "Signature " <> encodeUtf8 (encodeBase64 sig)
  where Signature sig = dsign secretKey (encodeUtf8 reqStringToSign)


authStringToSign :: Request -> UUID -> Text
authStringToSign req reqId
  = decodeUtf8 (method req) <> "\n"
  <> decodeUtf8 (path req) <> "\n"
  <> decodeUtf8 (queryString req) <> "\n"
  <> pack (toString reqId)
