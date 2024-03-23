module Lib.Command.Create
  ( create
  , createCommand
  , CreateCommand(..)
  ) where

import Options.Applicative

import Lib.Command.Create.Group
import Lib.Command.Create.Policy
import Lib.Command.Create.User


data CreateCommand
  = CreateGroupCommand !CreateGroup
  | CreatePolicyCommand !CreatePolicy
  | CreateUserCommand !CreateUser
  deriving (Show)


create :: CreateCommand -> IO ()
create (CreateGroupCommand createGroupData) = createGroup createGroupData
create (CreatePolicyCommand createPolicyData) = createPolicy createPolicyData
create (CreateUserCommand createUserData) = createUser createUserData


createCommand :: Parser CreateCommand
createCommand = subparser
  ( command "group"
    (info (CreateGroupCommand <$> createGroupOptions) (progDesc "Create a group"))
  <> command "policy"
    (info (CreatePolicyCommand <$> createPolicyOptions) (progDesc "Create a policy"))
  <> command "user"
    (info (CreateUserCommand <$> createUserOptions) (progDesc "Create a user"))
  )
