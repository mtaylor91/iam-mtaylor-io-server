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

import IAM.Authentication
import IAM.Config (configEmail, configSecretKey, configMaybeSessionToken,  headerPrefix)


newtype ClientAuth = ClientAuth { clientAuth :: Request -> IO Request }


clientAuthInfo :: IO ClientAuth
clientAuthInfo = do
  email <- configEmail
  secretKey <- configSecretKey
  maybeSessionToken <- configMaybeSessionToken
  case decodeSecretKey $ pack secretKey of
    Nothing ->
      throw $ userError "Invalid secret key"
    Just secretKey' ->
      return $ mkClientAuth email secretKey' $ pack <$> maybeSessionToken


mkClientAuth :: String -> SecretKey -> Maybe Text -> ClientAuth
mkClientAuth email secretKey maybeSessionToken = ClientAuth $ \req -> do
  case lookup "Authorization" $ requestHeaders req of
    Just _ -> return req
    Nothing -> do
      requestId <- nextRandom
      let email' = pack email
          publicKey = encodePublicKey secretKey
          authorization = authHeader reqStringToSign secretKey
          reqStringToSign = authStringToSign req requestId maybeSessionToken
      return $ req
        { requestHeaders = requestHeaders req ++
          authReqHeaders authorization email' publicKey requestId maybeSessionToken
        }


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


authStringToSign :: Request -> UUID -> Maybe Text -> Text
authStringToSign req reqId maybeSessionToken
  = decodeUtf8 $ stringToSign m h p q reqId maybeSessionToken
  where m = method req
        h = host req
        p = path req
        q = queryString req


authReqHeaders ::
  ByteString -> Text -> Text -> UUID -> Maybe Text ->  [(CI ByteString, ByteString)]
authReqHeaders authorization email publicKey requestId Nothing =
  [ ("Authorization", authorization)
  , (headerPrefix' <> "-User-Id", encodeUtf8 email)
  , (headerPrefix' <> "-Public-Key", encodeUtf8 publicKey)
  , (headerPrefix' <> "-Request-Id", encodeUtf8 $ pack $ toString requestId)
  ]
authReqHeaders authorization email publicKey requestId (Just token) =
  (headerPrefix' <> "-Session-Token", encodeUtf8 token) :
  authReqHeaders authorization email publicKey requestId Nothing


headerPrefix' :: CI ByteString
headerPrefix' = mk (encodeUtf8 $ pack headerPrefix)
