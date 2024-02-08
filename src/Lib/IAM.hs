{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DuplicateRecordFields #-}
module Lib.IAM
  ( User(..)
  , Group(..)
  , Membership(..)
  , UserId(..)
  , GroupId(..)
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text
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
