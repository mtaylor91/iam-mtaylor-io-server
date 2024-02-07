module Lib.DB ( DB(..) ) where

import Data.Text

import Lib.Group
import Lib.User


class DB db where

  -- | getUser returns a user from the database by its email.
  getUser :: db -> Text -> IO (Maybe User)

  -- | listUsers returns a list of all users in the database.
  listUsers :: db -> IO [User]

  -- | createUser adds a new user to the database.
  createUser :: db -> User -> IO ()

  -- | updateUser updates a user in the database.
  updateUser :: db -> Text -> User -> IO ()

  -- | deleteUser removes a user from the database by its email.
  deleteUser :: db -> Text -> IO ()

  -- | getGroup returns a group from the database by its name.
  getGroup :: db -> Text -> IO (Maybe Group)

  -- | listGroups returns a list of all groups in the database.
  listGroups :: db -> IO [Group]

  -- | createGroup adds a new group to the database.
  createGroup :: db -> Group -> IO ()

  -- | updateGroup updates a group in the database.
  updateGroup :: db -> Text -> Group -> IO ()

  -- | deleteGroup removes a group from the database by its name.
  deleteGroup :: db -> Text -> IO ()
