module IAM.Command.Delete
  ( delete
  , deleteCommand
  , DeleteCommand(..)
  ) where

import Options.Applicative

import IAM.Command.Delete.Group
import IAM.Command.Delete.Policy
import IAM.Command.Delete.User


data DeleteCommand
  = DeleteGroupCommand !DeleteGroup
  | DeletePolicyCommand !DeletePolicy
  | DeleteUserCommand !DeleteUser
  deriving (Show)


delete :: DeleteCommand -> IO ()
delete (DeleteGroupCommand deleteGroupData) = deleteGroup deleteGroupData
delete (DeletePolicyCommand deletePolicyData) = deletePolicy deletePolicyData
delete (DeleteUserCommand deleteUserData) = deleteUser deleteUserData


deleteCommand :: Parser DeleteCommand
deleteCommand = subparser
  ( command "group"
    (info (DeleteGroupCommand <$> deleteGroupOptions) (progDesc "Delete a group"))
  <> command "policy"
    (info (DeletePolicyCommand <$> deletePolicyOptions) (progDesc "Delete a policy"))
  <> command "user"
    (info (DeleteUserCommand <$> deleteUserOptions) (progDesc "Delete a user"))
  )
