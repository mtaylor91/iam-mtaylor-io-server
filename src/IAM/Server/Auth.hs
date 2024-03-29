{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Auth
  ( authContext
  , authHandler
  , stringToSign
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

import IAM.Config (headerPrefix)
import IAM.Server.IAM.DB
import IAM.Server.IAM.Policy
import IAM.Types


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
  { authRequestAuthorization :: !ByteString
  , authRequestHost :: !ByteString
  , authRequestPublicKey :: !PublicKey
  , authRequestUserId :: !UserId
  , authRequestId :: !UUID
  } deriving (Eq, Show)


type instance AuthServerData (AuthProtect "signature-auth") = Auth


authContext :: DB db => ByteString -> db -> Context (AuthHandler Request Auth ': '[])
authContext host db = authHandler host db :. EmptyContext


authHandler :: DB db => ByteString -> db -> AuthHandler Request Auth
authHandler host db = mkAuthHandler $ \req -> do
  (authReq, user) <- authenticate host db req
  authorize db req $ Authentication user authReq


authenticate :: DB db => ByteString -> db -> Request -> Handler (AuthRequest, User)
authenticate host db req = do
  let maybeAuth = do
        authHeader <- lookup "Authorization" (requestHeaders req)
        hostHeader <- lookup "Host" (requestHeaders req)
        userIdString <- lookupHeader req "User-Id"
        publicKeyBase64 <- lookupHeader req "Public-Key"
        requestIdString <- lookupHeader req "Request-Id"
        uid <- parseUserId $ decodeUtf8 userIdString
        pk <- parsePublicKey publicKeyBase64
        requestId <- fromString $ unpack $ decodeUtf8 requestIdString
        return $ AuthRequest authHeader hostHeader pk uid requestId
   in case maybeAuth of
    Just authReq -> do
      result <- liftIO $ runExceptT $ getUser db $ authRequestUserId authReq
      case result of
        Right user -> do
          let authHeader = authRequestAuthorization authReq
              method = requestMethod req
              path = rawPathInfo req
              query = rawQueryString req
              authStringToSign = stringToSign method host path query requestId
              requestId = authRequestId authReq
              pk = authRequestPublicKey authReq
          if verifySignature user pk authHeader authStringToSign
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
verifySignature user pk authHeader authStringToSign =
  pk `elem` fmap userPublicKey (userPublicKeys user)
  && verifySignature' (decodeSignature =<< extractSignature authHeader)
    where
      verifySignature' :: Maybe Signature -> Bool
      verifySignature' (Just sig) = dverify pk authStringToSign sig
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


-- | Lookup a given header in the request
lookupHeader :: Request -> HeaderName -> Maybe ByteString
lookupHeader req header = lookup header' (requestHeaders req) where
  header' = mk (encodeUtf8 $ pack headerPrefix) <> "-" <> header


-- | String to sign to authenticate the request
stringToSign :: Method -> ByteString -> ByteString -> ByteString -> UUID -> ByteString
stringToSign method host path query requestId
  = method <> "\n"
  <> host <> "\n"
  <> path <> "\n"
  <> query <> "\n"
  <> encodeUtf8 (toText requestId)
