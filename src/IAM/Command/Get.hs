module IAM.Command.Get
  ( get
  , getCommand
  , GetCommand(..)
  ) where

import Data.Text
import Options.Applicative

import IAM.Command.Get.Group
import IAM.Command.Get.Policy
import IAM.Command.Get.User


data GetCommand
  = GetGroup !Text
  | GetPolicy !Text
  | GetUser !(Maybe Text)
  deriving (Show)


get :: GetCommand -> IO ()
get (GetGroup group') = getGroup group'
get (GetPolicy policy') = getPolicy policy'
get (GetUser email') = getUser email'


getCommand :: Parser GetCommand
getCommand = subparser
  ( command "group"
    ( info
      ( GetGroup <$> argument str (metavar "GROUP")
      ) (progDesc "Get a group")
    )
  <> command "policy"
    ( info
      ( GetPolicy <$> argument str (metavar "POLICY")
      ) (progDesc "Get a policy")
    )
  <> command "user"
    ( info
      ( GetUser <$> optional ( argument str (metavar "EMAIL") )
      ) (progDesc "Get a user")
    )
  )
