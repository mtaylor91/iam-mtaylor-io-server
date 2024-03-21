module Lib.Command.Get
  ( get
  , getCommand
  , GetCommand(..)
  ) where

import Data.Text
import Options.Applicative

import Lib.Command.Get.Group
import Lib.Command.Get.User


data GetCommand
  = GetUser !(Maybe Text)
  | GetGroup !Text
  deriving (Show)


get :: GetCommand -> IO ()
get (GetUser email') = getUser email'
get (GetGroup group') = getGroup group'


getCommand :: Parser GetCommand
getCommand = subparser
  ( command "group"
    ( info
      ( GetGroup <$> argument str (metavar "GROUP")
      ) (progDesc "Get a group")
    )
  <> command "user"
    ( info
      ( GetUser <$> optional ( argument str (metavar "EMAIL") )
      ) (progDesc "Get a user")
    )
  )
