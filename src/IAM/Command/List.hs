module IAM.Command.List
  ( list
  , listCommand
  , ListCommand(..)
  ) where

import Options.Applicative

import IAM.Command.List.Groups
import IAM.Command.List.Logins
import IAM.Command.List.Policies
import IAM.Command.List.Sessions
import IAM.Command.List.Users


data ListCommand
  = ListGroups !ListGroupsOptions
  | ListLogins !ListLoginsOptions
  | ListPolicies !ListPoliciesOptions
  | ListSessions !ListSessionsOptions
  | ListUsers !ListUsersOptions
  deriving (Show)


list :: ListCommand -> IO ()
list (ListGroups opts) = listGroups opts
list (ListLogins opts) = listLogins opts
list (ListPolicies opts) = listPolicies opts
list (ListSessions opts) = listSessions opts
list (ListUsers opts) = listUsers opts


listCommand :: Parser ListCommand
listCommand = subparser
  ( command "groups"
    (info (ListGroups <$> listGroupsOptions) (progDesc "List groups"))
  <> command "logins"
    (info (ListLogins <$> listLoginsOptions) (progDesc "List logins"))
  <> command "policies"
    (info (ListPolicies <$> listPoliciesOptions) (progDesc "List policies"))
  <> command "sessions"
    (info (ListSessions <$> listSessionsOptions) (progDesc "List sessions"))
  <> command "users"
    (info (ListUsers <$> listUsersOptions) (progDesc "List users"))
  )
