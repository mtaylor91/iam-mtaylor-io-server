module IAM.Command.Create
  ( create
  , createCommand
  , CreateCommand(..)
  ) where

import Options.Applicative

import IAM.Command.Create.Group
import IAM.Command.Create.Policy
import IAM.Command.Create.User


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
