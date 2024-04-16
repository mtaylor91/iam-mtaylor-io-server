{-# LANGUAGE OverloadedStrings #-}
module IAM.Group
  ( module IAM.Group
  ) where

import Data.Aeson
import Data.Maybe
import Data.Text

import IAM.GroupIdentifier
import IAM.UserIdentifier
import IAM.Policy


data Group = Group
  { groupId :: !GroupId
  , groupName :: !(Maybe Text)
  , groupUsers :: ![UserIdentifier]
  , groupPolicies :: ![PolicyIdentifier]
  } deriving (Eq, Show)

instance FromJSON Group where
  parseJSON (Object obj) = do
    uuid <- obj .: "id"
    maybeName <- obj .:? "name"
    maybeUsers <- obj .:? "users"
    maybePolicies <- obj .:? "policies"
    let users = fromMaybe [] maybeUsers
    let policies = fromMaybe [] maybePolicies
    return $ Group uuid maybeName users policies
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Group where
  toJSON (Group (GroupUUID uuid) maybeName users policies) = object
    [ "id" .= uuid
    , "name" .= maybeName
    , "users" .= users
    , "policies" .= policies
    ]
