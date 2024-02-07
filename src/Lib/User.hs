{-# LANGUAGE TemplateHaskell #-}
module Lib.User ( User(..) ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text


data User = User
  { userEmail :: !Text
  , userIsAdmin :: !Bool
  , userGroups :: ![Text]
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''User)
