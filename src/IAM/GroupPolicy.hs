{-# LANGUAGE OverloadedStrings #-}
module IAM.GroupPolicy
  ( module IAM.GroupPolicy
  ) where

import Data.Aeson

import IAM.GroupIdentifier
import IAM.Policy


data GroupPolicyAttachment = GroupPolicyAttachment
  { groupPolicyAttachmentGroupId :: !GroupId
  , groupPolicyAttachmentPolicyId :: !PolicyId
  } deriving (Eq, Show)

instance FromJSON GroupPolicyAttachment where
  parseJSON (Object obj) = do
    g <- obj .: "group"
    p <- obj .: "policy"
    return $ GroupPolicyAttachment g p
  parseJSON _ = fail "Invalid JSON"

instance ToJSON GroupPolicyAttachment where
  toJSON (GroupPolicyAttachment g p) = object
    [ "group" .= g
    , "policy" .= p
    ]
