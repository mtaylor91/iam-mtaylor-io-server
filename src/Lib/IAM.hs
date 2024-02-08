{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DuplicateRecordFields #-}
module Lib.IAM
  ( User(..)
  , UserId(..)
  , Group(..)
  , GroupId(..)
  , Effect(..)
  , Action(..)
  , Policy(..)
  , PolicyRule(..)
  , UserPolicyAttachment(UserPolicyAttachment)
  , GroupPolicyAttachment(GroupPolicyAttachment)
  , Membership(..)
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text
import Data.UUID
import Servant


newtype UserId = UserEmailId { email :: Text } deriving (Eq, Show)

$(deriveJSON defaultOptions ''UserId)

instance FromHttpApiData UserId where
  parseUrlPiece = Right . UserEmailId


newtype GroupId = GroupNameId { name :: Text } deriving (Eq, Show)

$(deriveJSON defaultOptions ''GroupId)

instance FromHttpApiData GroupId where
  parseUrlPiece = Right . GroupNameId


data User = User
  { userId :: !UserId
  , groups :: ![GroupId]
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''User)


data Group = Group
  { groupId :: !GroupId
  , users :: ![UserId]
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Group)


data Membership = Membership
  { userId :: !UserId
  , groupId :: !GroupId
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Membership)


data Effect = Allow | Deny deriving (Eq, Show)

$(deriveJSON defaultOptions ''Effect)


data Action = Read | Write | Delete deriving (Eq, Show)

$(deriveJSON defaultOptions ''Action)


data PolicyRule = PolicyRule
  { effect :: !Effect
  , action :: !Action
  , resource :: !Text
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''PolicyRule)


data Policy = Policy
  { policyId :: !UUID
  , statements :: ![PolicyRule]
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Policy)


data UserPolicyAttachment = UserPolicyAttachment
  { userId :: !UserId
  , policyId :: !UUID
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''UserPolicyAttachment)


data GroupPolicyAttachment = GroupPolicyAttachment
  { groupId :: !GroupId
  , policyId :: !UUID
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''GroupPolicyAttachment)
