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
import Data.ByteString (ByteString, splitAt, takeWhile)
import Data.ByteString.Base64
import Data.CaseInsensitive
import Data.Text (Text, pack, unpack)
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Types
import Network.Wai
import Prelude hiding (takeWhile)
import Servant
import Servant.Server.Experimental.Auth
import qualified Data.ByteString.Lazy as LBS

import IAM.Authentication
import IAM.Config (headerPrefix)
import IAM.Error
import IAM.Identifiers
import IAM.Policy
import IAM.Server.Context
import IAM.Server.DB
import IAM.Session
import IAM.User


data Auth = Auth
  { authentication :: !Authentication
  , authorization :: !Authorization
  } deriving (Eq, Show)


data Authentication = Authentication
  { authUser :: !User
  , authRequest :: !AuthRequest
  } deriving (Eq, Show)


data Authorization = Authorization
  { authPolicies :: ![Policy]
  , authSession :: !(Maybe Session)
  } deriving (Eq, Show)


data AuthRequest = AuthRequest
  { authRequestAuthorization :: !ByteString
  , authRequestHost :: !ByteString
  , authRequestPublicKey :: !PublicKey
  , authRequestSessionToken :: !(Maybe Text)
  , authRequestUserId :: !UserIdentifier
  , authRequestId :: !UUID
  } deriving (Eq, Show)


type instance AuthServerData (AuthProtect "signature-auth") = Auth


authContext :: DB db => Text -> Ctx db -> Context (AuthHandler Request Auth ': '[])
authContext host ctx = authHandler host ctx :. EmptyContext


authHandler :: DB db => Text -> Ctx db -> AuthHandler Request Auth
authHandler host ctx = mkAuthHandler $ \req -> do
  (authReq, user) <- authenticate host ctx req
  authorize host ctx req $ Authentication user authReq


authenticate :: DB db => Text -> Ctx db -> Request -> Handler (AuthRequest, User)
authenticate host ctx req = do
  let maybeSessionToken = do
        token <- lookupHeader req "Session-Token"
        return $ decodeUtf8 token
  let maybeAuth = do
        authHeader <- lookup "Authorization" (requestHeaders req)
        hostHeader <- lookup "Host" (requestHeaders req)
        userIdString <- lookupHeader req "User-Id"
        publicKeyBase64 <- lookupHeader req "Public-Key"
        requestIdString <- lookupHeader req "Request-Id"
        uid <- parseUserId $ decodeUtf8 userIdString
        pk <- parsePublicKey publicKeyBase64
        requestId <- fromString $ unpack $ decodeUtf8 requestIdString
        return $ AuthRequest authHeader hostHeader pk maybeSessionToken uid requestId
   in case maybeAuth of
    Just authReq -> do
      result <- liftIO $ runExceptT $ getUser (ctxDB ctx) $ authRequestUserId authReq
      case result of
        Right user -> do
          case authReqError authReq user of
            Nothing -> return (authReq, user)
            Just err -> throwError $ err401 { errBody = LBS.fromStrict $ encodeUtf8 err }
        Left (NotFound _ _) -> throwError $ err401 { errBody = "User not found" }
        Left err -> do
          liftIO $ print err
          throwError err500
    Nothing -> do
      throwError $ err401 { errBody = "Missing or invalid authentication headers" }
  where
    authReqError :: AuthRequest -> User -> Maybe Text
    authReqError authReq user =
      let authHeader = authRequestAuthorization authReq
          method = requestMethod req
          path = rawPathInfo req
          query = rawQueryString req
          reqHost = removeHostPort $ authRequestHost authReq
          requestId = authRequestId authReq
          maybeSessionToken = authRequestSessionToken authReq
          pk = authRequestPublicKey authReq
          signed = stringToSign method reqHost path query requestId maybeSessionToken
       in if reqHost /= encodeUtf8 host
            then Just "Invalid host"
            else if not $ verifySignature user pk authHeader signed
              then Just "Invalid signature"
              else Nothing
    removeHostPort :: ByteString -> ByteString
    removeHostPort = takeWhile (not . (==) 58)


authorize :: DB db => Text -> Ctx db -> Request -> Authentication -> Handler Auth
authorize host ctx req authN = do
  callerUserId <- case authRequestUserId $ authRequest authN of
    UserId uid -> return uid
    UserIdAndEmail uid _ -> return uid
    UserEmail email -> do
      result <- liftIO $ runExceptT $ getUserId (ctxDB ctx) $ UserEmail email
      case result of
        Right uid ->
          return uid
        Left (NotFound r n) ->
          throwError $ err401 { errBody = t r <> " " <> t n <> " not found" }
        Left e -> do
          liftIO $ print e
          throwError err500

  maybeSession <- case authRequestSessionToken $ authRequest authN of
    Nothing -> return Nothing
    Just token -> do
      let uid = UserId callerUserId
      result <- liftIO $ runExceptT $ getSessionByToken (ctxDB ctx) uid token
      case result of
        Right session ->
          return $ Just session
        Left (NotFound r n) ->
          throwError $ err401 { errBody = t r <> " " <> t n <> " not found" }
        Left e -> do
          liftIO $ print e
          throwError err500
  let dbOp = listPoliciesForUser (ctxDB ctx) callerUserId host
  policiesResult <- liftIO $ runExceptT dbOp
  case policiesResult of
    Right policies -> do
      if authorized req policies
        then let authZ = Authorization policies maybeSession in return $ Auth authN authZ
        else throwError err403
    Left e -> do
      liftIO $ print e
      throwError err500

  where

  t :: Text -> LBS.ByteString
  t = LBS.fromStrict . encodeUtf8


authorized :: Request ->  [Policy] -> Bool
authorized req policies = isAuthorized reqAction reqResource $ policyRules policies
  where
    reqResource = decodeUtf8 $ rawPathInfo req
    reqAction = actionFromMethod $ requestMethod req


parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey s =
  case decodeBase64 s of
    Right bs -> Just $ PublicKey bs
    Left _ -> Nothing


parseUserId :: Text -> Maybe UserIdentifier
parseUserId s =
  case fromString (unpack s) of
    Just uuid -> Just $ UserId $ UserUUID uuid
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
