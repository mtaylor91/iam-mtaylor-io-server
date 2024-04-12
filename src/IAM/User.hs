{-# LANGUAGE OverloadedStrings #-}
module IAM.User
  ( module IAM.User
  ) where

import Crypto.Sign.Ed25519
import Data.Aeson
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding

import IAM.Identifiers
import IAM.Policy


data User = User
  { userId :: !UserId
  , userEmail :: !(Maybe Text)
  , userGroups :: ![GroupIdentifier]
  , userPolicies :: ![PolicyId]
  , userPublicKeys :: ![UserPublicKey]
  } deriving (Eq, Show)

instance FromJSON User where
  parseJSON (Object obj) = do
    uid <- obj .: "id"
    groups <- obj .: "groups"
    policies <- obj .: "policies"
    publicKeys <- obj .: "publicKeys"
    maybeEmail <- obj .:? "email"
    return $ User uid maybeEmail groups policies publicKeys
  parseJSON _ = fail "Invalid JSON"

instance ToJSON User where
  toJSON (User (UserUUID uuid) email groups policies pks) = object
    [ "id" .= uuid
    , "email" .= email
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= toJSON pks
    ]


data UserPublicKey = UserPublicKey
  { userPublicKey :: !PublicKey
  , userPublicKeyDescription :: !Text
  } deriving (Eq, Show)


instance FromJSON UserPublicKey where
  parseJSON (Object obj) = do
    key <- obj .: "key"
    description <- obj .: "description"
    case decodeBase64 $ encodeUtf8 key of
      Left _ -> fail "Invalid JSON"
      Right bs -> return $ UserPublicKey (PublicKey bs) description
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserPublicKey where
  toJSON (UserPublicKey key description) = object
    [ "description" .= description
    , "key" .= encodeBase64 (unPublicKey key)
    ]
