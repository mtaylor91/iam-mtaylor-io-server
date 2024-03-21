module Lib.Command.Get
  ( get
  , getCommand
  , GetCommand(..)
  ) where

import Data.Text
import Options.Applicative

import Lib.Command.Get.User


newtype GetCommand
  = UserGet (Maybe Text)
  deriving (Show)


get :: GetCommand -> IO ()
get (UserGet email') = getUser email'


getCommand :: Parser GetCommand
getCommand = subparser
  ( command "user"
    ( info
      ( UserGet
        <$> optional ( argument str (metavar "EMAIL") )
      ) (progDesc "Get a user")
    )
  )
