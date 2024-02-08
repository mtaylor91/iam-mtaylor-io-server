module Lib.Handlers
  ( getUserHandler
  , listUsersHandler
  , createUserHandler
  , deleteUserHandler
  , getGroupHandler
  , listGroupsHandler
  , createGroupHandler
  , deleteGroupHandler
  , getPolicyHandler
  , listPoliciesHandler
  , createPolicyHandler
  , deletePolicyHandler
  , createMembershipHandler
  , deleteMembershipHandler
  ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.UUID
import Servant

import Lib.IAM
import Lib.IAM.DB

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

getPolicyHandler :: DB db => db -> UUID -> Handler Policy
getPolicyHandler db policy = do
  result <- liftIO $ runExceptT $ getPolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

listPoliciesHandler :: DB db => db -> Handler [UUID]
listPoliciesHandler db = do
  result <- liftIO $ runExceptT $ listPolicies db
  case result of
    Right policies' -> return policies'
    Left err        -> throwError $ dbError err

createPolicyHandler :: DB db => db -> Policy -> Handler Policy
createPolicyHandler db policy = do
  result <- liftIO $ runExceptT $ createPolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

deletePolicyHandler :: DB db => db -> UUID -> Handler Policy
deletePolicyHandler db policy = do
  result <- liftIO $ runExceptT $ deletePolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

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
