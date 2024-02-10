{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
module Lib.Auth
  ( authContext
  , authHandler
  , authStringToSign
  , Auth(..)
  ) where

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


data Auth = Auth
  { authUser :: !User
  , authRequest :: !AuthRequest
  } deriving (Eq, Show)


data AuthRequest = AuthRequest
  { authRequestHeader :: !ByteString
  , authRequestUserId :: !UserId
  , authRequestPublicKey :: !PublicKey
  , authRequestId :: !UUID
  } deriving (Eq, Show)


type instance AuthServerData (AuthProtect "signature-auth") = Auth


authContext :: DB db => db -> Context (AuthHandler Request Auth ': '[])
authContext db = authHandler db :. EmptyContext


authHandler :: DB db => db -> AuthHandler Request Auth
authHandler db = mkAuthHandler $ \req -> do
  (authReq, user) <- authenticate db req
  return $ Auth user authReq


authenticate :: DB db => db -> Request -> Handler (AuthRequest, User)
authenticate db req =
  let maybeAuth = do
        userIdString <- lookup "X-User-Id" (requestHeaders req)
        authorization <- lookup "Authorization" (requestHeaders req)
        publicKeyBase64 <- lookup "X-Public-Key" (requestHeaders req)
        requestIdString <- lookup "X-Request-Id" (requestHeaders req)
        uid <- parseUserId $ decodeUtf8 userIdString
        pk <- parsePublicKey publicKeyBase64
        requestId <- fromString $ unpack $ decodeUtf8 requestIdString
        return $ AuthRequest authorization uid pk requestId
   in case maybeAuth of
    Just authReq -> do
      result <- liftIO $ runExceptT $ getUser db $ authRequestUserId authReq
      case result of
        Right user -> do
          let authorization = authRequestHeader authReq
              method = requestMethod req
              path = rawPathInfo req
              query = rawQueryString req
              stringToSign = authStringToSign method path query requestId
              requestId = authRequestId authReq
              pk = authRequestPublicKey authReq
          if verifySignature user pk authorization stringToSign
            then return (authReq, user)
            else throwError err401
        Left NotFound -> throwError err401
        Left _ -> throwError err500
    Nothing -> throwError err401


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
verifySignature user pk authorization stringToSign =
  pk `elem` userPublicKeys user
  && verifySignature' (decodeSignature =<< extractSignature authorization)
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
authStringToSign :: Method -> ByteString -> ByteString -> UUID -> ByteString
authStringToSign method path query requestId =
  method <> "\n" <> path <> "\n" <> query <> "\n" <> encodeUtf8 (toText requestId)
