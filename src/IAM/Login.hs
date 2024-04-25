{-# LANGUAGE OverloadedStrings #-}
module IAM.Login
  ( module IAM.Login
  ) where

import Data.Aeson
import Data.UUID

import IAM.User
import IAM.UserIdentifier


newtype LoginRequestId = LoginRequestId { unLoginRequestId :: UUID } deriving (Eq, Show)


data LoginRequest = LoginRequest
  { loginRequestUser :: UserIdentifier
  , loginRequestPublicKey :: UserPublicKey
  } deriving (Eq, Show)


instance FromJSON LoginRequest where
  parseJSON (Object obj) = do
    user <- obj .: "user"
    publicKey <- obj .: "publicKey"
    return $ LoginRequest user publicKey
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginRequest where
  toJSON (LoginRequest user publicKey) = object
    [ "user" .= user
    , "publicKey" .= publicKey
    ]


data LoginRequestStatus
  = LoginRequestPending
  | LoginRequestGranted
  | LoginRequestDenied
  deriving (Eq, Show)


instance FromJSON LoginRequestStatus where
  parseJSON (String "pending") = return LoginRequestPending
  parseJSON (String "granted") = return LoginRequestGranted
  parseJSON (String "denied") = return LoginRequestDenied
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginRequestStatus where
  toJSON LoginRequestPending = "pending"
  toJSON LoginRequestGranted = "granted"
  toJSON LoginRequestDenied = "denied"


data LoginRequestResponse = LoginRequestResponse
  { loginResponseUser :: UserIdentifier
  , loginResponseStatus :: LoginRequestStatus
  } deriving (Eq, Show)


instance FromJSON LoginRequestResponse where
  parseJSON (Object obj) = do
    user <- obj .: "user"
    session <- obj .: "session"
    return $ LoginRequestResponse user session
  parseJSON _ = fail "Invalid JSON"


instance ToJSON LoginRequestResponse where
  toJSON (LoginRequestResponse user session) = object
    [ "user" .= user
    , "session" .= session
    ]
