{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
module Lib.Auth (authContext, authHandler, authStringToSign) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString (ByteString, splitAt)
import Data.ByteString.Base64
import Data.Text (Text, unpack)
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Types
import Network.Wai
import Servant
import Servant.Server.Experimental.Auth

import Lib.IAM
import Lib.IAM.DB


type instance AuthServerData (AuthProtect "signature-auth") = User


authContext :: DB db => db -> Context (AuthHandler Request User ': '[])
authContext db = authHandler db :. EmptyContext


authHandler :: DB db => db -> AuthHandler Request User
authHandler db = mkAuthHandler handler where
  handler :: Request -> Handler User
  handler req =
    let maybeAuthHeader = lookup "Authorization" (requestHeaders req)
        maybeUserIdString = lookup "X-User-Id" (requestHeaders req)
        maybePublicKeyBase64 = lookup "X-Public-Key" (requestHeaders req)
     in case (maybeAuthHeader, maybeUserIdString, maybePublicKeyBase64) of
      (Just authHeader, Just userIdString, Just publicKeyBase64) ->
        let maybeUserId = parseUserId $ decodeUtf8 userIdString
            maybePublicKey = parsePublicKey publicKeyBase64
         in case (maybeUserId, maybePublicKey) of
          (Just uid, Just pk) -> do
            result <- liftIO $ runExceptT $ getUser db uid
            case result of
              Right user -> do
                let method = requestMethod req
                    path = rawPathInfo req
                    query = rawQueryString req
                    stringToSign = authStringToSign method path query
                if verifySignature user pk authHeader stringToSign
                  then return user
                  else throwError err401
              Left NotFound -> throwError err401
              Left _ -> throwError err500
          (_, _) -> throwError err401
      (_, _, _) -> throwError err401


parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey s =
  case decodeBase64 s of
    Right bs -> Just $ PublicKey bs
    Left _ -> Nothing


parseUserId :: Text -> Maybe UserId
parseUserId s =
  case fromString (unpack s) of
    Just uuid -> Just $ UserUUID uuid
    Nothing -> Just $ UserEmail s


verifySignature :: User -> PublicKey -> ByteString -> ByteString -> Bool
verifySignature user pk authHeader stringToSign =
  pk `elem` userPublicKeys user
  && verifySignature' (decodeSignature =<< extractSignature authHeader)
    where
      verifySignature' :: Maybe Signature -> Bool
      verifySignature' (Just sig) = dverify pk stringToSign sig
      verifySignature' _ = False


-- | Extract the signature from the Authorization header
extractSignature :: ByteString -> Maybe ByteString
extractSignature s =
  case Data.ByteString.splitAt 10 s of
    ("Signature ", bs) -> Just bs
    (_, _) -> Nothing


-- | Decode the signature from base64
decodeSignature :: ByteString -> Maybe Signature
decodeSignature s =
  case decodeBase64 s of
    Right bs -> Just $ Signature bs
    Left _ -> Nothing


-- | Auth string to sign
authStringToSign :: Method -> ByteString -> ByteString -> ByteString
authStringToSign method path query = method <> "\n" <> path <> "\n" <> query
