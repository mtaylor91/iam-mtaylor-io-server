module Lib.Command.Create
  ( create
  , createCommand
  , CreateCommand(..)
  ) where

import Options.Applicative

import Lib.Command.Create.Policy
import Lib.Command.Create.User


data CreateCommand
  = CreatePolicyCommand !CreatePolicy
  | CreateUserCommand !CreateUser
  deriving (Show)


create :: CreateCommand -> IO ()
create (CreatePolicyCommand createPolicyData) = createPolicy createPolicyData
create (CreateUserCommand createUserData) = createUser createUserData


createCommand :: Parser CreateCommand
createCommand = subparser
  ( command "policy"
    (info (CreatePolicyCommand <$> createPolicyOptions) (progDesc "Create a policy"))
  <> command "user"
    (info (CreateUserCommand <$> createUserOptions) (progDesc "Create a user"))
  )
