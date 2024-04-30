{-# LANGUAGE OverloadedStrings #-}
module IAM.User
  ( module IAM.User
  ) where

import Data.Aeson
import Data.Text
import Data.Text.Encoding
import Data.UUID
import Text.Email.Validate

import IAM.Error
import IAM.GroupIdentifier
import IAM.UserIdentifier
import IAM.UserPublicKey
import IAM.Policy


data User = User
  { userId :: !UserId
  , userName :: !(Maybe Text)
  , userEmail :: !(Maybe Text)
  , userGroups :: ![GroupIdentifier]
  , userPolicies :: ![PolicyIdentifier]
  , userPublicKeys :: ![UserPublicKey]
  } deriving (Eq, Show)

instance FromJSON User where
  parseJSON (Object obj) = do
    uid <- obj .: "id"
    groups <- obj .: "groups"
    policies <- obj .: "policies"
    publicKeys <- obj .: "publicKeys"
    maybeName <- obj .:? "name"
    maybeEmail <- obj .:? "email"
    return $ User uid maybeName maybeEmail groups policies publicKeys
  parseJSON _ = fail "Invalid JSON"

instance ToJSON User where
  toJSON (User (UserUUID uuid) name email groups policies pks) = object
    [ "id" .= uuid
    , "name" .= name
    , "email" .= email
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= toJSON pks
    ]


data UserUpdate = UserUpdate
  { userUpdateName :: !(Maybe Text)
  , userUpdateEmail :: !(Maybe Text)
  } deriving (Eq, Show)

instance FromJSON UserUpdate where
  parseJSON (Object obj) = do
    maybeName <- obj .:? "name"
    maybeEmail <- obj .:? "email"
    return $ UserUpdate maybeName maybeEmail
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserUpdate where
  toJSON (UserUpdate name email) = object
    [ "name" .= name
    , "email" .= email
    ]


validateUser :: User -> Either Error User
validateUser u = do
  validateUserName $ userName u
  validateUserEmail $ userEmail u
  return u


validateUserUpdate :: UserUpdate -> Either Error UserUpdate
validateUserUpdate u = do
  validateUserName $ userUpdateName u
  validateUserEmail $ userUpdateEmail u
  return u


validateUserName :: Maybe Text -> Either Error ()
validateUserName Nothing = Right ()
validateUserName (Just name) = do
  if name == ""
    then Left $ ValidationError "Name cannot be empty."
    else Right ()
  if isValid $ encodeUtf8 name
    then Left $ ValidationError "Name cannot be an email address."
    else Right ()
  case fromText name of
    Just _ ->
      Left $ ValidationError "Name cannot be a UUID."
    Nothing ->
      Right ()


validateUserEmail :: Maybe Text -> Either Error ()
validateUserEmail Nothing = Right ()
validateUserEmail (Just email) = do
  if email == ""
    then Left $ ValidationError "Email cannot be empty."
    else Right ()
  if isValid $ encodeUtf8 email
    then Right ()
    else Left $ ValidationError "Invalid email address."
