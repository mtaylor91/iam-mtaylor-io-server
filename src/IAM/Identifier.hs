{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module IAM.Identifier
  ( module IAM.Identifier
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.Aeson
import Data.ByteString.Base64.URL
import Data.Text

import IAM.GroupIdentifier
import IAM.Login
import IAM.Policy
import IAM.Session
import IAM.UserIdentifier


data Identifier
  = LoginIdentifier LoginRequestId
  | UserIdentifier' UserIdentifier
  | GroupIdentifier GroupIdentifier
  | PolicyIdentifier PolicyIdentifier
  | SessionIdentifier (Maybe SessionId)
  | UserGroupIdentifier UserIdentifier GroupIdentifier
  | UserPolicyIdentifier UserIdentifier PolicyIdentifier
  | UserPublicKeyIdentifier UserId PublicKey
  | GroupPolicyIdentifier GroupIdentifier PolicyIdentifier
  deriving (Show, Eq)

instance ToJSON Identifier where
  toJSON (LoginIdentifier rid) = object
    [ "kind" .= ("Login" :: Text)
    , "login" .= toJSON rid
    ]
  toJSON (UserIdentifier' uid) = object
    [ "kind" .= ("User" :: Text)
    , "user" .= toJSON uid
    ]
  toJSON (GroupIdentifier gid) = object
    [ "kind" .= ("Group" :: Text)
    , "group" .= toJSON gid
    ]
  toJSON (PolicyIdentifier pid) = object
    [ "kind" .= ("Policy" :: Text)
    , "policy" .= toJSON pid
    ]
  toJSON (SessionIdentifier msid) = object
    [ "kind" .= ("Session" :: Text)
    , "session" .= toJSON msid
    ]
  toJSON (UserGroupIdentifier uid gid) = object
    [ "kind" .= ("Membership" :: Text)
    , "user" .= toJSON uid
    , "group" .= toJSON gid
    ]
  toJSON (UserPolicyIdentifier uid pid) = object
    [ "kind" .= ("UserPolicy" :: Text)
    , "user" .= toJSON uid
    , "policy" .= toJSON pid
    ]
  toJSON (UserPublicKeyIdentifier uid pk) = object
    [ "kind" .= ("UserPublicKey" :: Text)
    , "user" .= toJSON uid
    , "public-key" .= encodeBase64 (unPublicKey pk)
    ]
  toJSON (GroupPolicyIdentifier gid pid) = object
    [ "kind" .= ("GroupPolicy" :: Text)
    , "group" .= toJSON gid
    , "policy" .= toJSON pid
    ]

instance FromJSON Identifier where
  parseJSON (Object obj) = do
    kind :: Text <- obj .: "kind"
    case kind of
      "Login" -> LoginIdentifier <$> obj .: "login"
      "User" -> UserIdentifier' <$> obj .: "user"
      "Group" -> GroupIdentifier <$> obj .: "group"
      "Policy" -> PolicyIdentifier <$> obj .: "policy"
      "Session" -> SessionIdentifier <$> obj .: "session"
      "Membership" -> UserGroupIdentifier <$> obj .: "user" <*> obj .: "group"
      "UserPolicy" -> UserPolicyIdentifier <$> obj .: "user" <*> obj .: "policy"
      "GroupPolicy" -> GroupPolicyIdentifier <$> obj .: "group" <*> obj .: "policy"
      _ -> fail "Invalid JSON"
  parseJSON _ = fail "Invalid JSON"
