{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Auth
  ( authN
  , authZ
  , authAddr
  , authContext
  , authHandler
  , stringToSign
  , Auth(..)
  , Authentication(..)
  , Authorization(..)
  , AuthRequest(..)
  ) where

import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.ByteString (ByteString, splitAt, takeWhile)
import Data.ByteString.Base64.URL
import Data.CaseInsensitive
import Data.Text (Text, pack, unpack)
import Data.Text.Encoding
import Data.Time.Clock
import Data.UUID
import Network.HTTP.Types
import Network.Socket (SockAddr)
import Network.Wai
import Prelude hiding (takeWhile)
import Servant
import Servant.Server.Experimental.Auth
import Text.Email.Validate

import IAM.Authentication
import IAM.Config (headerPrefix)
import IAM.Error
import IAM.Policy
import IAM.Server.Context
import IAM.Server.DB
import IAM.Session
import IAM.User
import IAM.UserIdentifier
import IAM.UserPublicKey


data Auth
  = SignatureAuth !Authentication !Authorization !SockAddr
  | Unauthenticated !SockAddr
  deriving (Eq, Show)

authN :: Auth -> Maybe Authentication
authN (SignatureAuth auth _ _) = Just auth
authN _ = Nothing

authZ :: Auth -> Maybe Authorization
authZ (SignatureAuth _ auth _) = Just auth
authZ _ = Nothing

authAddr :: Auth -> SockAddr
authAddr (SignatureAuth _ _ addr) = addr
authAddr (Unauthenticated addr) = addr


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
  let addr = remoteHost req
  result <- authenticate host ctx req
  case result of
    Just (authReq, user) -> do
      authZ' <- authorize host ctx req $ Authentication user authReq
      return $ SignatureAuth (Authentication user authReq) authZ' addr
    Nothing -> return $ Unauthenticated addr


authenticate :: DB db => Text -> Ctx db -> Request -> Handler (Maybe (AuthRequest, User))
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
        return $ AuthRequest
          { authRequestAuthorization = authHeader
          , authRequestHost = hostHeader
          , authRequestPublicKey = pk
          , authRequestSessionToken = maybeSessionToken
          , authRequestUserId = uid
          , authRequestId = requestId
          }
   in case maybeAuth of
    Just authReq -> do
      result <- liftIO $ runExceptT $ getUser (ctxDB ctx) $ authRequestUserId authReq
      case result of
        Right user -> do
          case authReqError authReq user of
            Nothing -> return $ Just (authReq, user)
            Just err -> errorHandler $ AuthenticationFailed err
        Left (NotFound _) -> do
          errorHandler $ AuthenticationFailed UserNotFound
        Left (InternalError e) -> do
          errorHandler $ InternalError e
        Left e ->
          errorHandler $ InternalError $ pack $ show e
    Nothing -> do
      return Nothing
  where
    authReqError :: AuthRequest -> User -> Maybe AuthenticationError
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
            then Just InvalidHost
            else if not $ verifySignature user pk authHeader signed
              then Just InvalidSignature
              else Nothing
    removeHostPort :: ByteString -> ByteString
    removeHostPort = takeWhile (not . (==) 58)


authorize :: DB db =>
  Text -> Ctx db -> Request -> Authentication -> Handler Authorization
authorize host ctx req authN' = do
  let callerUserId = userId $ authUser authN'

  now <- liftIO getCurrentTime
  maybeSession <- case authRequestSessionToken $ authRequest authN' of
    Nothing -> return Nothing
    Just token -> do
      let uid = UserIdentifier (Just callerUserId) Nothing Nothing
      result <- liftIO $ runExceptT $ getSessionByToken (ctxDB ctx) uid token
      case result of
        Right session | sessionExpiration session > now ->
          return $ Just session
        Right _expiredSession ->
          errorHandler $ AuthenticationFailed SessionExpired
        Left (NotFound _) ->
          errorHandler $ AuthenticationFailed SessionNotFound
        Left (InternalError e) ->
          errorHandler $ InternalError e
        Left e ->
          errorHandler $ InternalError $ pack $ show e
  let dbOp = listPoliciesForUser (ctxDB ctx) callerUserId host
  policiesResult <- liftIO $ runExceptT dbOp
  case policiesResult of
    Right policies -> do
      if authorized req policies
        then return $ Authorization policies maybeSession
        else errorHandler NotAuthorized
    Left (InternalError e) -> errorHandler $ InternalError e
    Left e -> errorHandler $ InternalError $ pack $ show e


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
    Just uuid -> Just $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing
    Nothing ->
      if isValid $ encodeUtf8 s
      then Just $ UserIdentifier Nothing Nothing (Just s)
      else Just $ UserIdentifier Nothing (Just s) Nothing


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
