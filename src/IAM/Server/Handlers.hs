module IAM.Server.Handlers
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
  , createUserPolicyAttachmentHandler
  , deleteUserPolicyAttachmentHandler
  , createGroupPolicyAttachmentHandler
  , deleteGroupPolicyAttachmentHandler
  ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.UUID
import Servant

import IAM.Server.Auth
import IAM.Server.IAM.DB
import IAM.Server.IAM.Policy
import IAM.Types

dbError :: DBError -> ServerError
dbError AlreadyExists  = err409
dbError NotFound       = err404
dbError InternalError  = err500
dbError NotImplemented = err501

getUserHandler :: DB db => db -> Auth -> UserId -> Handler User
getUserHandler db _ uid = do
  result <- liftIO $ runExceptT $ getUser db uid
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

listUsersHandler :: DB db => db -> Auth -> Handler [UserId]
listUsersHandler db _ = do
  result <- liftIO $ runExceptT $ listUsers db
  case result of
    Right users' -> return users'
    Left err     -> throwError $ dbError err

createUserHandler :: DB db => db -> Auth -> User -> Handler User
createUserHandler db _ userPrincipal = do
  result <- liftIO $ runExceptT $ createUser db userPrincipal
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

deleteUserHandler :: DB db => db -> Auth -> UserId -> Handler UserId
deleteUserHandler db _ uid = do
  result <- liftIO $ runExceptT $ deleteUser db uid
  case result of
    Right user' -> return user'
    Left err    -> throwError $ dbError err

getGroupHandler :: DB db => db -> Auth -> GroupId -> Handler Group
getGroupHandler db _ gid = do
  result <- liftIO $ runExceptT $ getGroup db gid
  case result of
    Right group' -> return group'
    Left err     -> throwError $ dbError err

listGroupsHandler :: DB db => db -> Auth -> Handler [GroupId]
listGroupsHandler db _ = do
  result <- liftIO $ runExceptT $ listGroups db
  case result of
    Right groups' -> return groups'
    Left err      -> throwError $ dbError err

createGroupHandler :: DB db => db -> Auth -> Group -> Handler Group
createGroupHandler db _ group = do
  result <- liftIO $ runExceptT $ createGroup db group
  case result of
    Right group' -> return group'
    Left err -> throwError $ dbError err

deleteGroupHandler :: DB db => db -> Auth -> GroupId -> Handler GroupId
deleteGroupHandler db _ gid = do
  result <- liftIO $ runExceptT $ deleteGroup db gid
  case result of
    Right () -> return gid
    Left err -> throwError $ dbError err

getPolicyHandler :: DB db => db -> Auth -> UUID -> Handler Policy
getPolicyHandler db _ policy = do
  result <- liftIO $ runExceptT $ getPolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

listPoliciesHandler :: DB db => db -> Auth -> Handler [UUID]
listPoliciesHandler db _ = do
  result <- liftIO $ runExceptT $ listPolicies db
  case result of
    Right pids -> return pids
    Left err   -> throwError $ dbError err

createPolicyHandler :: DB db => db -> Auth -> Policy -> Handler Policy
createPolicyHandler db auth policy = do
  let callerPolicies = authPolicies $ authorization auth
  if policy `isAllowedBy` policyRules callerPolicies
    then createPolicy'
    else throwError err403
  where
    createPolicy' = do
      result <- liftIO $ runExceptT $ createPolicy db policy
      case result of
        Right policy' -> return policy'
        Left err      -> throwError $ dbError err

deletePolicyHandler :: DB db => db -> Auth -> UUID -> Handler Policy
deletePolicyHandler db _ policy = do
  result <- liftIO $ runExceptT $ deletePolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> throwError $ dbError err

createMembershipHandler :: DB db => db -> Auth -> Membership -> Handler Membership
createMembershipHandler db _ (Membership uid gid) = do
  result <- liftIO $ runExceptT $ createMembership db uid gid
  case result of
    Right membership -> return membership
    Left err         -> throwError $ dbError err

deleteMembershipHandler :: DB db => db -> Auth -> GroupId -> UserId -> Handler Membership
deleteMembershipHandler db _ gid uid = do
  result <- liftIO $ runExceptT $ deleteMembership db uid gid
  case result of
    Right membership -> return membership
    Left err         -> throwError $ dbError err

createUserPolicyAttachmentHandler :: DB db =>
  db -> Auth -> UserId -> UUID -> Handler UserPolicyAttachment
createUserPolicyAttachmentHandler db auth uid pid = do
  result0 <- liftIO $ runExceptT $ getPolicy db pid
  case result0 of
    Right policy -> do
      if policy `isAllowedBy` policyRules callerPolicies
        then createUserPolicyAttachment'
        else throwError err403
    Left err -> throwError $ dbError err
  where
    callerPolicies = authPolicies $ authorization auth
    createUserPolicyAttachment' = do
      result <- liftIO $ runExceptT $ createUserPolicyAttachment db uid pid
      case result of
        Right attachment -> return attachment
        Left err         -> throwError $ dbError err

deleteUserPolicyAttachmentHandler :: DB db =>
  db -> Auth -> UserId -> UUID -> Handler UserPolicyAttachment
deleteUserPolicyAttachmentHandler db _ uid pid = do
  result <- liftIO $ runExceptT $ deleteUserPolicyAttachment db uid pid
  case result of
    Right attachment -> return attachment
    Left err         -> throwError $ dbError err

createGroupPolicyAttachmentHandler :: DB db =>
  db -> Auth -> GroupId -> UUID -> Handler GroupPolicyAttachment
createGroupPolicyAttachmentHandler db auth gid pid = do
  result <- liftIO $ runExceptT $ getPolicy db pid
  case result of
    Right policy -> do
      if policy `isAllowedBy` policyRules callerPolicies
        then createGroupPolicyAttachment'
        else throwError err403
    Left err -> throwError $ dbError err
  where
    callerPolicies = authPolicies $ authorization auth
    createGroupPolicyAttachment' = do
      result <- liftIO $ runExceptT $ createGroupPolicyAttachment db gid pid
      case result of
        Right attachment -> return attachment
        Left err         -> throwError $ dbError err

deleteGroupPolicyAttachmentHandler :: DB db =>
  db -> Auth -> GroupId -> UUID -> Handler GroupPolicyAttachment
deleteGroupPolicyAttachmentHandler db _ gid pid = do
  result <- liftIO $ runExceptT $ deleteGroupPolicyAttachment db gid pid
  case result of
    Right attachment -> return attachment
    Left err         -> throwError $ dbError err
