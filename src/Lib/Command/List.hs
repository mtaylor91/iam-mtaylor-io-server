module Lib.Command.List
  ( list
  , listCommand
  , ListCommand(..)
  ) where

import Options.Applicative

import Lib.Command.List.Groups
import Lib.Command.List.Policies
import Lib.Command.List.Users


data ListCommand
  = ListGroups
  | ListPolicies
  | ListUsers
  deriving (Show)


list :: ListCommand -> IO ()
list ListGroups = listGroups
list ListPolicies = listPolicies
list ListUsers = listUsers


listCommand :: Parser ListCommand
listCommand = subparser
  ( command "groups"
    (info (pure ListGroups) (progDesc "List groups"))
  <> command "policies"
    (info (pure ListPolicies) (progDesc "List policies"))
  <> command "users"
    (info (pure ListUsers) (progDesc "List users"))
  )
