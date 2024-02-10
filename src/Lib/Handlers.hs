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
dbError NotFound      = err404
dbError InternalError = err500

getUserHandler :: DB db => db -> User -> UserId -> Handler User
getUserHandler db _ uid = do
  result <- liftIO $ runExceptT $ getUser db uid
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

listUsersHandler :: DB db => db -> User -> Handler [UserId]
listUsersHandler db _ = do
  result <- liftIO $ runExceptT $ listUsers db
  case result of
    Right users' -> return users'
    Left err     -> throwError $ dbError err

createUserHandler :: DB db => db -> User -> UserPrincipal -> Handler UserPrincipal
createUserHandler db _ userPrincipal = do
  result <- liftIO $ runExceptT $ createUser db userPrincipal
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

deleteUserHandler :: DB db => db -> User -> UserId -> Handler UserId
deleteUserHandler db _ uid = do
  result <- liftIO $ runExceptT $ deleteUser db uid
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

getGroupHandler :: DB db => db -> User -> GroupId -> Handler Group
getGroupHandler db _ gid = do
  result <- liftIO $ runExceptT $ getGroup db gid
  case result of
    Right group' -> return group'
    Left err     -> throwError $ dbError err

listGroupsHandler :: DB db => db -> User -> Handler [GroupId]
listGroupsHandler db _ = do
  result <- liftIO $ runExceptT $ listGroups db
  case result of
    Right groups' -> return groups'
    Left err      -> throwError $ dbError err

createGroupHandler :: DB db => db -> User -> Group -> Handler Group
createGroupHandler db _ group = do
  result <- liftIO $ runExceptT $ createGroup db group
  case result of
    Right group' -> return group'
    Left err -> throwError $ dbError err

deleteGroupHandler :: DB db => db -> User -> GroupId -> Handler GroupId
deleteGroupHandler db _ gid = do
  result <- liftIO $ runExceptT $ deleteGroup db gid
  case result of
    Right () -> return gid
    Left err -> throwError $ dbError err

getPolicyHandler :: DB db => db -> User -> UUID -> Handler Policy
getPolicyHandler db _ policy = do
  result <- liftIO $ runExceptT $ getPolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

listPoliciesHandler :: DB db => db -> User -> Handler [UUID]
listPoliciesHandler db _ = do
  result <- liftIO $ runExceptT $ listPolicies db
  case result of
    Right policies' -> return policies'
    Left err        -> throwError $ dbError err

createPolicyHandler :: DB db => db -> User -> Policy -> Handler Policy
createPolicyHandler db _ policy = do
  result <- liftIO $ runExceptT $ createPolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

deletePolicyHandler :: DB db => db -> User -> UUID -> Handler Policy
deletePolicyHandler db _ policy = do
  result <- liftIO $ runExceptT $ deletePolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

createMembershipHandler :: DB db => db -> User -> Membership -> Handler Membership
createMembershipHandler db _ (Membership uid gid) = do
  result <- liftIO $ runExceptT $ createMembership db uid gid
  case result of
    Right membership -> return membership
    Left err         -> throwError $ dbError err

deleteMembershipHandler :: DB db => db -> User -> GroupId -> UserId -> Handler Membership
deleteMembershipHandler db _ gid uid = do
  result <- liftIO $ runExceptT $ deleteMembership db uid gid
  case result of
    Right membership -> return membership
    Left err         -> throwError $ dbError err
