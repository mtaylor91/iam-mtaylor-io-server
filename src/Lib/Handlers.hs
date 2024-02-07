module Lib.Handlers
  ( getUserHandler
  , listUsersHandler
  , createUserHandler
  , updateUserHandler
  , deleteUserHandler
  , getGroupHandler
  , listGroupsHandler
  , createGroupHandler
  , updateGroupHandler
  , deleteGroupHandler
  ) where

import Control.Monad.IO.Class
import Data.Text hiding (group)
import Servant

import Lib.DB
import Lib.Group
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

getGroupHandler :: DB db => db -> Text -> Handler Group
getGroupHandler db name = do
  maybeGroup <- liftIO $ getGroup db name
  case maybeGroup of
    Just group -> return group
    Nothing    -> throwError err404

listGroupsHandler :: DB db => db -> Handler [Group]
listGroupsHandler db = liftIO $ listGroups db

createGroupHandler :: DB db => db -> Group -> Handler Group
createGroupHandler db group = do
  liftIO $ createGroup db group
  return group

updateGroupHandler :: DB db => db -> Text -> Group -> Handler Group
updateGroupHandler db name group = do
  liftIO $ updateGroup db name group
  return group

deleteGroupHandler :: DB db => db -> Text -> Handler (Maybe Group)
deleteGroupHandler db name = do
  maybeGroup <- liftIO $ getGroup db name
  case maybeGroup of
    Just group -> do
      liftIO $ deleteGroup db name
      return $ Just group
    Nothing    -> return Nothing
