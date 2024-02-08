{-# LANGUAGE FlexibleContexts #-}
module Lib.DB ( DB(..), DBError(..) ) where

import Control.Monad.IO.Class
import Control.Monad.Except

import Lib.IAM


data DBError
  = AlreadyExists
  | NotFound
  | InternalError
  deriving (Show, Eq)


class DB db where

  -- | getUser returns a user from the database by its email.
  getUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> m User

  -- | listUsers returns a list of all users in the database.
  listUsers :: (MonadIO m, MonadError DBError m) =>
    db -> m [UserId]

  -- | createUser adds a new user to the database.
  createUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> m ()

  -- | deleteUser removes a user from the database by its email.
  deleteUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> m ()

  -- | getGroup returns a group from the database by its name.
  getGroup :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> m Group

  -- | listGroups returns a list of all groups in the database.
  listGroups :: (MonadIO m, MonadError DBError m) =>
    db -> m [GroupId]

  -- | createGroup adds a new group to the database.
  createGroup :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> m ()

  -- | deleteGroup removes a group from the database by its name.
  deleteGroup :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> m ()

  -- | createMembership adds a user to a group.
  createMembership :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> GroupId -> m Membership

  -- | deleteMembership removes a user from a group.
  deleteMembership :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> GroupId -> m Membership
