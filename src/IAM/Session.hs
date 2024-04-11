{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.Session
  ( module IAM.Session
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.ByteString.Base64
import Data.Text
import Data.Time.Clock
import Data.UUID
import Data.UUID.V4
import Servant
import System.Entropy
import Text.Read (readMaybe)

import IAM.Identifiers


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
  , sessionUser :: !UserId
  , sessionExpiration :: !UTCTime
  } deriving (Eq, Show)

instance ToJSON Session where
  toJSON (Session sid user expiration) = object
    [ "id" .= sid
    , "user" .= user
    , "expiration" .= expiration
    ]

instance FromJSON Session where
  parseJSON = withObject "Session" $ \o -> do
    sid <- o .: "id"
    user <- o .: "user"
    expiration <- o .: "expiration"
    return $ Session sid user expiration


refreshSession :: Session -> Session
refreshSession s = s { sessionExpiration = addUTCTime 3600 $ sessionExpiration s }


data CreateSession = CreateSession
  { createSessionId :: !SessionId
  , createSessionUser :: !UserId
  , createSessionToken :: !Text
  , createSessionExpiration :: !UTCTime
  } deriving (Eq, Show)

instance ToJSON CreateSession where
  toJSON (CreateSession sid user token expiration) = object
    [ "id" .= sid
    , "user" .= user
    , "token" .= token
    , "expiration" .= expiration
    ]

instance FromJSON CreateSession where
  parseJSON = withObject "CreateSession" $ \o -> do
    sid <- o .: "id"
    user <- o .: "user"
    token <- o .: "token"
    expiration <- o .: "expiration"
    return $ CreateSession sid user token expiration


createSession :: UserId -> IO CreateSession
createSession uid = do
  uuid <- nextRandom
  now <- getCurrentTime
  randomBytes <- getEntropy 32
  let sid = SessionUUID uuid
  let token = encodeBase64 randomBytes
  let expiration = addUTCTime 3600 now
  return $ CreateSession sid uid token expiration


toSession :: CreateSession -> Session
toSession (CreateSession sid uid _ expiration) = Session sid uid expiration
