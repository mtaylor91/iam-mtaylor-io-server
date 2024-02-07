module Lib.InMemory ( InMemory(..) ) where

import Control.Concurrent.STM
import Data.List (find)

import Lib.DB
import Lib.User

-- | InMemory is an in-memory implementation of the DB typeclass.
-- It uses an IORef to store a list of users.
newtype InMemory = InMemory (TVar [User])


instance DB InMemory where

  -- | getUser returns a user from the list of users.
  getUser (InMemory users) email = find (\u -> email == userEmail u) <$> readTVarIO users

  -- | listUsers returns the list of users.
  listUsers (InMemory users) = readTVarIO users

  -- | createUser adds a user to the list of users.
  createUser (InMemory users) user = atomically $ modifyTVar' users (\us -> us ++ [user])

  -- | updateUser updates a user in the list of users.
  updateUser (InMemory users) email user =
    atomically $ modifyTVar' users $ map (\u -> if userEmail u == email then user else u)

  -- | deleteUser removes a user from the list of users.
  deleteUser (InMemory users) email =
    atomically $ modifyTVar' users $ filter (\u -> userEmail u /= email)
