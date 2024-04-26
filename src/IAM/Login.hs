{-# LANGUAGE OverloadedStrings #-}
module IAM.Login
  ( module IAM.Login
  ) where

import Data.Aeson
import Data.Time.Clock
import Data.UUID
import Servant

import IAM.Ip
import IAM.UserPublicKey
import IAM.UserIdentifier


newtype LoginRequestId = LoginRequestId { unLoginRequestId :: UUID } deriving (Eq, Show)


instance FromJSON LoginRequestId where
  parseJSON (String s) = case fromText s of
    Just uuid -> return $ LoginRequestId uuid
    Nothing -> fail "Invalid UUID"
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginRequestId where
  toJSON (LoginRequestId uuid) = String $ toText uuid


instance FromHttpApiData LoginRequestId where
  parseUrlPiece s = case fromText s of
    Just uuid -> Right $ LoginRequestId uuid
    Nothing -> Left "Invalid UUID"


instance ToHttpApiData LoginRequestId where
  toUrlPiece (LoginRequestId uuid) = toText uuid


data LoginRequest = LoginRequest
  { loginRequestId :: !LoginRequestId
  , loginRequestUser :: !UserIdentifier
  , loginRequestPublicKey :: !UserPublicKey
  } deriving (Eq, Show)


instance FromJSON LoginRequest where
  parseJSON (Object obj) = do
    lid <- obj .: "id"
    user <- obj .: "user"
    publicKey <- obj .: "publicKey"
    return $ LoginRequest lid user publicKey
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginRequest where
  toJSON (LoginRequest lid user publicKey) = object
    [ "id" .= lid
    , "user" .= user
    , "publicKey" .= publicKey
    ]


createLoginRequest :: LoginRequest -> IpAddr -> UserId -> IO (LoginResponse s)
createLoginRequest (LoginRequest lid _ publicKey) ip uid = do
  now <- getCurrentTime
  let expires = addUTCTime 3600 now
  return $ LoginResponse ip lid uid publicKey expires Nothing LoginRequestPending


data LoginStatus
  = LoginRequestPending
  | LoginRequestGranted
  | LoginRequestDenied
  deriving (Eq, Show)


instance FromJSON LoginStatus where
  parseJSON (String "pending") = return LoginRequestPending
  parseJSON (String "granted") = return LoginRequestGranted
  parseJSON (String "denied") = return LoginRequestDenied
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginStatus where
  toJSON LoginRequestPending = "pending"
  toJSON LoginRequestGranted = "granted"
  toJSON LoginRequestDenied = "denied"


data LoginResponse s = LoginResponse
  { loginResponseIp :: IpAddr
  , loginResponseRequest :: LoginRequestId
  , loginResponseUserId :: UserId
  , loginResponsePublicKey :: UserPublicKey
  , loginResponseExpires :: UTCTime
  , loginResponseSession :: Maybe s
  , loginResponseStatus :: LoginStatus
  } deriving (Eq, Show)


instance FromJSON s => FromJSON (LoginResponse s) where
  parseJSON (Object obj) = do
    ip <- obj .: "ip"
    lid <- obj .: "id"
    user <- obj .: "user"
    publicKey <- obj .: "publicKey"
    expires <- obj .: "expires"
    session <- obj .: "session"
    status <- obj .: "status"
    return $ LoginResponse ip lid user publicKey expires session status
  parseJSON _ = fail "Invalid JSON"


instance ToJSON s => ToJSON (LoginResponse s) where
  toJSON (LoginResponse ip lid user publicKey expires session status) = object
    [ "ip" .= ip
    , "id" .= lid
    , "user" .= user
    , "publicKey" .= publicKey
    , "expires" .= expires
    , "session" .= session
    , "status" .= status
    ]
