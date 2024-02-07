module Lib.Handlers
  ( getUserHandler
  , listUsersHandler
  , createUserHandler
  , updateUserHandler
  , deleteUserHandler
  ) where

import Control.Monad.IO.Class
import Data.Text
import Servant

import Lib.DB
import Lib.User

getUserHandler :: DB db => db -> Text -> Handler User
getUserHandler db email = do
  maybeUser <- liftIO $ getUser db email
  case maybeUser of
    Just user -> return user
    Nothing   -> throwError err404

listUsersHandler :: DB db => db -> Handler [User]
listUsersHandler db = liftIO $ listUsers db

createUserHandler :: DB db => db -> User -> Handler User
createUserHandler db user = do
  liftIO $ createUser db user
  return user

updateUserHandler :: DB db => db -> Text -> User -> Handler User
updateUserHandler db email user = do
  liftIO $ updateUser db email user
  return user

deleteUserHandler :: DB db => db -> Text -> Handler (Maybe User)
deleteUserHandler db email = do
  maybeUser <- liftIO $ getUser db email
  case maybeUser of
    Just user -> do
      liftIO $ deleteUser db email
      return $ Just user
    Nothing   -> return Nothing
