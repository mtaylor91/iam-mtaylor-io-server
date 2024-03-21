module Lib.Command.Create
  ( create
  , createCommand
  , CreateCommand(..)
  ) where

import Options.Applicative

import Lib.Command.Create.User


newtype CreateCommand
  = CreateUserCommand CreateUser
  deriving (Show)


create :: CreateCommand -> IO ()
create (CreateUserCommand createUserData) = createUser createUserData


createCommand :: Parser CreateCommand
createCommand = subparser
  ( command "user"
    (info (CreateUserCommand <$> createUserOptions) (progDesc "Create a user"))
  )
