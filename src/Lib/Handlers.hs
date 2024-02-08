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
import Servant

import Lib.DB
import Lib.IAM

getUserHandler :: DB db => db -> UserId -> Handler User
getUserHandler db user = do
  maybeUser <- liftIO $ getUser db user
  case maybeUser of
    Just user' -> return user'
    Nothing    -> throwError err404

listUsersHandler :: DB db => db -> Handler [UserId]
listUsersHandler db = liftIO $ listUsers db

createUserHandler :: DB db => db -> UserId -> Handler UserId
createUserHandler db user = do
  maybeUser <- liftIO $ createUser db user
  case maybeUser of
    Just user' -> return user'
    Nothing    -> throwError err409

deleteUserHandler :: DB db => db -> UserId -> Handler UserId
deleteUserHandler db user = do
  maybeUser <- liftIO $ deleteUser db user
  case maybeUser of
    Just user' -> return user'
    Nothing    -> throwError err404

getGroupHandler :: DB db => db -> GroupId -> Handler Group
getGroupHandler db group = do
  maybeGroup <- liftIO $ getGroup db group
  case maybeGroup of
    Just group' -> return group'
    Nothing     -> throwError err404

listGroupsHandler :: DB db => db -> Handler [GroupId]
listGroupsHandler db = liftIO $ listGroups db

createGroupHandler :: DB db => db -> GroupId -> Handler GroupId
createGroupHandler db group = do
  maybeGroup <- liftIO $ createGroup db group
  case maybeGroup of
    Just group' -> return group'
    Nothing     -> throwError err409

deleteGroupHandler :: DB db => db -> GroupId -> Handler GroupId
deleteGroupHandler db group = do
  maybeGroup <- liftIO $ deleteGroup db group
  case maybeGroup of
    Just group' -> return group'
    Nothing     -> throwError err404

createMembershipHandler :: DB db => db -> Membership -> Handler Membership
createMembershipHandler db (Membership user group) = do
  maybeMembership <- liftIO $ createMembership db user group
  case maybeMembership of
    Just (user', group') -> return $ Membership user' group'
    Nothing              -> throwError err409

deleteMembershipHandler :: DB db => db -> GroupId -> UserId -> Handler Membership
deleteMembershipHandler db group user = do
  maybeMembership <- liftIO $ deleteMembership db user group
  case maybeMembership of
    Just (user', group') -> return $ Membership user' group'
    Nothing              -> throwError err404
