module Lib.DB ( DB(..) ) where

import Data.Text

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
