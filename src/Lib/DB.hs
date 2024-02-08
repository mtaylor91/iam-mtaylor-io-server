module Lib.DB ( DB(..) ) where

import Control.Monad.IO.Class

import Lib.IAM


class DB db where

  -- | getUser returns a user from the database by its email.
  getUser :: MonadIO m => db -> UserId -> m (Maybe User)

  -- | listUsers returns a list of all users in the database.
  listUsers :: MonadIO m => db -> m [UserId]

  -- | createUser adds a new user to the database.
  createUser :: MonadIO m => db -> UserId -> m (Maybe UserId)

  -- | deleteUser removes a user from the database by its email.
  deleteUser :: MonadIO m => db -> UserId -> m (Maybe UserId)

  -- | getGroup returns a group from the database by its name.
  getGroup :: MonadIO m => db -> GroupId -> m (Maybe Group)

  -- | listGroups returns a list of all groups in the database.
  listGroups :: MonadIO m => db -> m [GroupId]

  -- | createGroup adds a new group to the database.
  createGroup :: MonadIO m => db -> GroupId -> m (Maybe GroupId)

  -- | deleteGroup removes a group from the database by its name.
  deleteGroup :: MonadIO m => db -> GroupId -> m (Maybe GroupId)

  -- | createMembership adds a user to a group.
  createMembership :: MonadIO m => db -> UserId -> GroupId -> m (Maybe (UserId, GroupId))

  -- | deleteMembership removes a user from a group.
  deleteMembership :: MonadIO m => db -> UserId -> GroupId -> m (Maybe (UserId, GroupId))
