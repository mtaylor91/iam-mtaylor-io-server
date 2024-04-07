module IAM.Command.List
  ( list
  , listCommand
  , ListCommand(..)
  ) where

import Options.Applicative

import IAM.Command.List.Groups
import IAM.Command.List.Policies
import IAM.Command.List.Users


data ListCommand
  = ListGroups !ListGroupsOptions
  | ListPolicies !ListPoliciesOptions
  | ListUsers !ListUsersOptions
  deriving (Show)


list :: ListCommand -> IO ()
list (ListGroups opts) = listGroups opts
list (ListPolicies opts) = listPolicies opts
list (ListUsers opts) = listUsers opts


listCommand :: Parser ListCommand
listCommand = subparser
  ( command "groups"
    (info (ListGroups <$> listGroupsOptions) (progDesc "List groups"))
  <> command "policies"
    (info (ListPolicies <$> listPoliciesOptions) (progDesc "List policies"))
  <> command "users"
    (info (ListUsers <$> listUsersOptions) (progDesc "List users"))
  )
