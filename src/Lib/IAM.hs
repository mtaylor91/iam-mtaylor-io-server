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
  , Rule(..)
  , UserPolicyAttachment(UserPolicyAttachment)
  , GroupPolicyAttachment(GroupPolicyAttachment)
  , Membership(..)
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text
import Data.UUID
import Servant


data UserId
  = UserUUID !UUID
  | UserEmail !Text
  deriving (Eq, Show)

$(deriveJSON defaultOptions { sumEncoding = UntaggedValue } ''UserId)

instance FromHttpApiData UserId where
  parseUrlPiece = Right . UserEmail


data GroupId
  = GroupUUID !UUID
  | GroupName !Text
  deriving (Eq, Show)

$(deriveJSON defaultOptions { sumEncoding = UntaggedValue } ''GroupId)

instance FromHttpApiData GroupId where
  parseUrlPiece = Right . GroupName


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


data Rule = Rule
  { effect :: !Effect
  , action :: !Action
  , resource :: !Text
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Rule)


data Policy = Policy
  { policyId :: !UUID
  , statements :: ![Rule]
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
