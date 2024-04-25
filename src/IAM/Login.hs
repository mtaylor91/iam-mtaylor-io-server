{-# LANGUAGE OverloadedStrings #-}
module IAM.Login
  ( module IAM.Login
  ) where

import Data.Aeson
import Data.UUID
import Servant

import IAM.Session
import IAM.User
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
  { loginRequestId :: LoginRequestId
  , loginRequestUser :: UserIdentifier
  , loginRequestPublicKey :: UserPublicKey
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


data LoginResponse = LoginResponse
  { loginResponseRequest :: LoginRequestId
  , loginResponseUser :: UserIdentifier
  , loginResponsePublicKey :: UserPublicKey
  , loginResponseSession :: Maybe Session
  , loginResponseStatus :: LoginStatus
  } deriving (Eq, Show)


instance FromJSON LoginResponse where
  parseJSON (Object obj) = do
    lid <- obj .: "id"
    user <- obj .: "user"
    publicKey <- obj .: "publicKey"
    session <- obj .: "session"
    status <- obj .: "status"
    return $ LoginResponse lid user publicKey session status
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginResponse where
  toJSON (LoginResponse lid user publicKey session status) = object
    [ "id" .= lid
    , "user" .= user
    , "publicKey" .= publicKey
    , "session" .= session
    , "status" .= status
    ]
