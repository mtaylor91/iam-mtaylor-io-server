{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
module Lib.Server.Auth
  ( authContext
  , authHandler
  , authStringToSign
  , Auth(..)
  , Authentication(..)
  , Authorization(..)
  ) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString (ByteString, splitAt)
import Data.ByteString.Base64
import Data.CaseInsensitive
import Data.Text (Text, pack, unpack)
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Types
import Network.Wai
import Servant
import Servant.Server.Experimental.Auth
import System.IO

import Lib.Config (headerPrefix)
import Lib.IAM
import Lib.Server.IAM.DB
import Lib.Server.IAM.Policy


data Auth = Auth
  { authentication :: !Authentication
  , authorization :: !Authorization
  } deriving (Eq, Show)


data Authentication = Authentication
  { authUser :: !User
  , authRequest :: !AuthRequest
  } deriving (Eq, Show)


newtype Authorization = Authorization
  { authPolicies :: [Policy]
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
  authorize db req $ Authentication user authReq


authenticate :: DB db => db -> Request -> Handler (AuthRequest, User)
authenticate db req = do
  let maybeAuth = do
        userIdString <- lookupHeader req "User-Id"
        authHeader <- lookup "Authorization" (requestHeaders req)
        publicKeyBase64 <- lookupHeader req "Public-Key"
        requestIdString <- lookupHeader req "Request-Id"
        uid <- parseUserId $ decodeUtf8 userIdString
        pk <- parsePublicKey publicKeyBase64
        requestId <- fromString $ unpack $ decodeUtf8 requestIdString
        return $ AuthRequest authHeader uid pk requestId
   in case maybeAuth of
    Just authReq -> do
      result <- liftIO $ runExceptT $ getUser db $ authRequestUserId authReq
      case result of
        Right user -> do
          let authHeader = authRequestHeader authReq
              method = requestMethod req
              path = rawPathInfo req
              query = rawQueryString req
              stringToSign = authStringToSign method path query requestId
              requestId = authRequestId authReq
              pk = authRequestPublicKey authReq
          liftIO $ putStrLn $ "Request string to sign: " <> unpack (decodeUtf8 stringToSign)
          liftIO $ hFlush stdout
          if verifySignature user pk authHeader stringToSign
            then return (authReq, user)
            else throwError $ err401 { errBody = "Invalid signature" }
        Left NotFound -> throwError $ err401 { errBody = "User not found" }
        Left _ -> throwError err500
    Nothing -> do
      throwError $ err401 { errBody = "Missing or invalid authentication headers" }


authorize :: DB db => db -> Request -> Authentication -> Handler Auth
authorize db req authN = do
  policiesResult <- liftIO $ runExceptT $ listPoliciesForUser db callerUserId
  case policiesResult of
    Right policies -> do
      if authorized req policies
        then let authZ = Authorization policies in return $ Auth authN authZ
        else throwError err403
    Left _ -> throwError err500
  where
    callerUserId = authRequestUserId $ authRequest authN


authorized :: Request ->  [Policy] -> Bool
authorized req policies = isAuthorized reqAction reqResource $ policyRules policies
  where
    reqResource = decodeUtf8 $ rawPathInfo req
    reqAction = case parseMethod $ requestMethod req of
      Right method -> case method of
        GET -> Read
        POST -> Write
        HEAD -> Read
        PUT -> Write
        DELETE -> Write
        TRACE -> Read
        CONNECT -> Read
        OPTIONS -> Read
        PATCH -> Write
      Left _ -> Write


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
authStringToSign :: Method -> ByteString -> ByteString -> UUID -> ByteString
authStringToSign method path query requestId =
  method <> "\n" <> path <> "\n" <> query <> "\n" <> encodeUtf8 (toText requestId)


-- | Lookup a given header in the request
lookupHeader :: Request -> HeaderName -> Maybe ByteString
lookupHeader req header = lookup header' (requestHeaders req) where
  header' = mk (encodeUtf8 $ pack headerPrefix) <> "-" <> header
