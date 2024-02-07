{-# LANGUAGE TemplateHaskell #-}
module Lib.Group ( Group(..) ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text


data Group = Group
  { groupName :: !Text
  , groupUsers :: !Text
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Group)
