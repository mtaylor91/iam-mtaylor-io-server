{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.Session
  ( module IAM.Session
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.ByteString.Base64.URL
import Data.Text
import Data.Time.Clock
import Data.UUID
import Data.UUID.V4
import Servant
import System.Entropy
import Text.Read (readMaybe)

import IAM.Ip
import IAM.UserIdentifier


newtype SessionId = SessionUUID { unSessionId :: UUID } deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''SessionId)

instance FromHttpApiData SessionId where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ SessionUUID uuid
    Nothing -> Left "Invalid UUID"

instance ToHttpApiData SessionId where
  toUrlPiece (SessionUUID uuid) = toText uuid


data Session = Session
  { sessionId :: !SessionId
  , sessionAddr :: !IpAddr
  , sessionUser :: !UserId
  , sessionExpiration :: !UTCTime
  } deriving (Eq, Show)

instance ToJSON Session where
  toJSON (Session sid addr user expiration) = object
    [ "id" .= sid
    , "user" .= user
    , "address" .= addr
    , "expiration" .= expiration
    ]

instance FromJSON Session where
  parseJSON = withObject "Session" $ \o -> do
    sid <- o .: "id"
    user <- o .: "user"
    addr <- o .: "address"
    expiration <- o .: "expiration"
    return $ Session sid addr user expiration


refreshSession :: Session -> Session
refreshSession s = s { sessionExpiration = addUTCTime 3600 $ sessionExpiration s }


toCreateSession :: Session -> Text -> CreateSession
toCreateSession (Session sid addr uid expiration) token =
  CreateSession sid addr uid token expiration


data CreateSession = CreateSession
  { createSessionId :: !SessionId
  , createSessionAddr :: !IpAddr
  , createSessionUser :: !UserId
  , createSessionToken :: !Text
  , createSessionExpiration :: !UTCTime
  } deriving (Eq, Show)

instance ToJSON CreateSession where
  toJSON (CreateSession sid addr user token expiration) = object
    [ "id" .= sid
    , "user" .= user
    , "token" .= token
    , "address" .= addr
    , "expiration" .= expiration
    ]

instance FromJSON CreateSession where
  parseJSON = withObject "CreateSession" $ \o -> do
    sid <- o .: "id"
    user <- o .: "user"
    token <- o .: "token"
    addr <- o .: "address"
    expiration <- o .: "expiration"
    return $ CreateSession sid addr user token expiration


createSession :: IpAddr -> UserId -> IO CreateSession
createSession addr uid = do
  uuid <- nextRandom
  now <- getCurrentTime
  randomBytes <- getEntropy 32
  let sid = SessionUUID uuid
  let token = encodeBase64 randomBytes
  let expiration = addUTCTime 3600 now
  return $ CreateSession sid addr uid token expiration


toSession :: CreateSession -> Session
toSession (CreateSession sid addr uid _ expiration) = Session sid addr uid expiration
