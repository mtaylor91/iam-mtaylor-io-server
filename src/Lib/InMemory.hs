module Lib.InMemory ( inMemory, InMemory(..) ) where

import Control.Concurrent.STM
import Data.Bifunctor (first, second)
import Data.List (find)

import Lib.DB
import Lib.Group
import Lib.User

-- | InMemory is an in-memory implementation of the DB typeclass.
-- It uses an IORef to store a list of users.
newtype InMemory = InMemory (TVar ([User], [Group]))


inMemory :: IO InMemory
inMemory = InMemory <$> newTVarIO ([], [])


instance DB InMemory where

  getUser (InMemory ref) email = do
    (users, _) <- readTVarIO ref
    return $ find (\u -> userEmail u == email) users

  listUsers (InMemory ref) = do
    (users, _) <- readTVarIO ref
    return users

  createUser (InMemory ref) user = do
    atomically $ modifyTVar' ref $ first (user:)

  updateUser (InMemory ref) email user = do
    atomically $ modifyTVar' ref $ first (map (\u ->
      if userEmail u == email then user else u))

  deleteUser (InMemory ref) email = do
    atomically $ modifyTVar' ref $ first (filter (\u -> userEmail u /= email))

  getGroup (InMemory ref) name = do
    (_, groups) <- readTVarIO ref
    return $ find (\g -> groupName g == name) groups

  listGroups (InMemory ref) = do
    (_, groups) <- readTVarIO ref
    return groups

  createGroup (InMemory ref) group = do
    atomically $ modifyTVar' ref $ second (group:)

  updateGroup (InMemory ref) name group = do
    atomically $ modifyTVar' ref $ second (map (\g ->
      if groupName g == name then group else g))

  deleteGroup (InMemory ref) name = do
    atomically $ modifyTVar' ref $ second (filter (\g -> groupName g /= name))
