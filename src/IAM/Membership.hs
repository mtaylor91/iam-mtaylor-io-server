{-# LANGUAGE OverloadedStrings #-}
module IAM.Membership
  ( module IAM.Membership
  ) where

import Data.Aeson

import IAM.GroupIdentifier
import IAM.UserIdentifier


data Membership = Membership
  { membershipUserId :: !UserId
  , membershipGroupId :: !GroupId
  } deriving (Eq, Show)

instance FromJSON Membership where
  parseJSON (Object obj) = do
    u <- obj .: "user"
    g <- obj .: "group"
    return $ Membership u g
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Membership where
  toJSON (Membership u g) = object
    [ "user" .= u
    , "group" .= g
    ]
