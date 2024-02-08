module Lib.Handlers
  ( getUserHandler
  , listUsersHandler
  , createUserHandler
  , deleteUserHandler
  , getGroupHandler
  , listGroupsHandler
  , createGroupHandler
  , deleteGroupHandler
  , createMembershipHandler
  , deleteMembershipHandler
  ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Servant

import Lib.DB
import Lib.IAM

dbError :: DBError -> ServerError
dbError AlreadyExists = err409
dbError NotFound       = err404
dbError InternalError  = err500

getUserHandler :: DB db => db -> UserId -> Handler User
getUserHandler db user = do
  result <- liftIO $ runExceptT $ getUser db user
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

listUsersHandler :: DB db => db -> Handler [UserId]
listUsersHandler db = do
  result <- liftIO $ runExceptT $ listUsers db
  case result of
    Right users' -> return users'
    Left err     -> throwError $ dbError err

createUserHandler :: DB db => db -> UserId -> Handler UserId
createUserHandler db user = do
  result <- liftIO $ runExceptT $ createUser db user
  case result of
    Right () -> return user
    Left err -> throwError $ dbError err

deleteUserHandler :: DB db => db -> UserId -> Handler UserId
deleteUserHandler db user = do
  result <- liftIO $ runExceptT $ deleteUser db user
  case result of
    Right () -> return user
    Left err -> throwError $ dbError err

getGroupHandler :: DB db => db -> GroupId -> Handler Group
getGroupHandler db group = do
  result <- liftIO $ runExceptT $ getGroup db group
  case result of
    Right group' -> return group'
    Left err     -> throwError $ dbError err

listGroupsHandler :: DB db => db -> Handler [GroupId]
listGroupsHandler db = do
  result <- liftIO $ runExceptT $ listGroups db
  case result of
    Right groups' -> return groups'
    Left err      -> throwError $ dbError err

createGroupHandler :: DB db => db -> GroupId -> Handler GroupId
createGroupHandler db group = do
  result <- liftIO $ runExceptT $ createGroup db group
  case result of
    Right () -> return group
    Left err -> throwError $ dbError err

deleteGroupHandler :: DB db => db -> GroupId -> Handler GroupId
deleteGroupHandler db group = do
  result <- liftIO $ runExceptT $ deleteGroup db group
  case result of
    Right () -> return group
    Left err -> throwError $ dbError err

createMembershipHandler :: DB db => db -> Membership -> Handler Membership
createMembershipHandler db (Membership user group) = do
  result <- liftIO $ runExceptT $ createMembership db user group
  case result of
    Right membership -> return membership
    Left err         -> throwError $ dbError err

deleteMembershipHandler :: DB db => db -> GroupId -> UserId -> Handler Membership
deleteMembershipHandler db group user = do
  result <- liftIO $ runExceptT $ deleteMembership db user group
  case result of
    Right membership -> return membership
    Left err         -> throwError $ dbError err
