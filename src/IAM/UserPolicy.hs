{-# LANGUAGE OverloadedStrings #-}
module IAM.UserPolicy
  ( module IAM.UserPolicy
  ) where

import Data.Aeson
import Data.UUID

import IAM.Identifiers


data UserPolicyAttachment = UserPolicyAttachment
  { userPolicyAttachmentUserId :: !UserId
  , userPolicyAttachmentPolicyId :: !UUID
  } deriving (Eq, Show)

instance FromJSON UserPolicyAttachment where
  parseJSON (Object obj) = do
    u <- obj .: "user"
    p <- obj .: "policy"
    return $ UserPolicyAttachment u p
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserPolicyAttachment where
  toJSON (UserPolicyAttachment u p) = object
    [ "user" .= u
    , "policy" .= p
    ]
