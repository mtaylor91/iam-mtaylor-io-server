{-# LANGUAGE OverloadedStrings #-}
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
  , createSessionHandler
  , listUserSessionsHandler
  , getUserSessionHandler
  , deleteUserSessionHandler
  , refreshUserSessionHandler
  , authorizeHandler
  ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.Maybe
import Data.UUID
import Servant

import IAM.Authorization
import IAM.Error
import IAM.Group
import IAM.GroupPolicy
import IAM.Identifiers
import IAM.Membership
import IAM.Policy
import IAM.Range
import IAM.Server.Auth
import IAM.Server.DB
import IAM.Session
import IAM.User
import IAM.UserPolicy


getUserHandler :: DB db => db -> Auth -> UserIdentifier -> Handler User
getUserHandler db auth uid = do
  requireSession auth
  result <- liftIO $ runExceptT $ getUser db uid
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


listUsersHandler ::
  DB db => db -> Auth -> Maybe Int -> Maybe Int -> Handler [UserIdentifier]
listUsersHandler db auth maybeOffset maybeLimit = do
  requireSession auth
  let offset = fromMaybe 0 maybeOffset
  result <- liftIO $ runExceptT $ listUsers db $ Range offset maybeLimit
  case result of
    Right users' -> return users'
    Left err     -> errorHandler err


createUserHandler :: DB db => db -> Auth -> User -> Handler User
createUserHandler db auth userPrincipal = do
  requireSession auth
  result <- liftIO $ runExceptT $ createUser db userPrincipal
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


deleteUserHandler :: DB db => db -> Auth -> UserIdentifier -> Handler User
deleteUserHandler db auth uid = do
  requireSession auth
  result <- liftIO $ runExceptT $ deleteUser db uid
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


getGroupHandler :: DB db => db -> Auth -> GroupIdentifier -> Handler Group
getGroupHandler db auth gid = do
  requireSession auth
  result <- liftIO $ runExceptT $ getGroup db gid
  case result of
    Right group' -> return group'
    Left err     -> errorHandler err


listGroupsHandler ::
  DB db => db -> Auth -> Maybe Int -> Maybe Int -> Handler [GroupIdentifier]
listGroupsHandler db auth maybeOffset maybeLimit = do
  requireSession auth
  let offset = fromMaybe 0 maybeOffset
  result <- liftIO $ runExceptT $ listGroups db $ Range offset maybeLimit
  case result of
    Right groups' -> return groups'
    Left err      -> errorHandler err


createGroupHandler :: DB db => db -> Auth -> Group -> Handler Group
createGroupHandler db auth group = do
  requireSession auth
  result <- liftIO $ runExceptT $ createGroup db group
  case result of
    Right group' -> return group'
    Left err -> errorHandler err


deleteGroupHandler :: DB db => db -> Auth -> GroupIdentifier -> Handler Group
deleteGroupHandler db auth gid = do
  requireSession auth
  result <- liftIO $ runExceptT $ deleteGroup db gid
  case result of
    Right g -> return g
    Left err -> errorHandler err


getPolicyHandler :: DB db => db -> Auth -> UUID -> Handler Policy
getPolicyHandler db auth policy = do
  requireSession auth
  result <- liftIO $ runExceptT $ getPolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> errorHandler err


listPoliciesHandler :: DB db => db -> Auth -> Maybe Int -> Maybe Int -> Handler [UUID]
listPoliciesHandler db auth maybeOffset maybeLimit = do
  requireSession auth
  let offset = fromMaybe 0 maybeOffset
  result <- liftIO $ runExceptT $ listPolicyIds db $ Range offset maybeLimit
  case result of
    Right pids -> return pids
    Left err   -> errorHandler err


createPolicyHandler :: DB db => db -> Auth -> Policy -> Handler Policy
createPolicyHandler db auth policy = do
  requireSession auth
  let callerPolicies = authPolicies $ authorization auth
  if policy `isAllowedBy` policyRules callerPolicies
    then createPolicy'
    else throwError err403
  where
    createPolicy' = do
      result <- liftIO $ runExceptT $ createPolicy db policy
      case result of
        Right policy' -> return policy'
        Left err      -> errorHandler err


deletePolicyHandler :: DB db => db -> Auth -> UUID -> Handler Policy
deletePolicyHandler db auth policy = do
  requireSession auth
  result <- liftIO $ runExceptT $ deletePolicy db policy
  case result of
    Right policy' -> return policy'
    Left err      -> errorHandler err


createMembershipHandler ::
  DB db => db -> Auth -> GroupIdentifier -> UserIdentifier -> Handler Membership
createMembershipHandler db auth gid uid = do
  requireSession auth
  result <- liftIO $ runExceptT $ createMembership db uid gid
  case result of
    Right membership -> return membership
    Left err         -> errorHandler err


deleteMembershipHandler ::
  DB db => db -> Auth -> GroupIdentifier -> UserIdentifier -> Handler Membership
deleteMembershipHandler db auth gid uid = do
  requireSession auth
  result <- liftIO $ runExceptT $ deleteMembership db uid gid
  case result of
    Right membership -> return membership
    Left err         -> errorHandler err


createUserPolicyAttachmentHandler :: DB db =>
  db -> Auth -> UserIdentifier -> UUID -> Handler UserPolicyAttachment
createUserPolicyAttachmentHandler db auth uid pid = do
  requireSession auth
  result0 <- liftIO $ runExceptT $ getPolicy db pid
  case result0 of
    Right policy -> do
      if policy `isAllowedBy` policyRules callerPolicies
        then createUserPolicyAttachment'
        else throwError err403
    Left err -> errorHandler err
  where
    callerPolicies = authPolicies $ authorization auth
    createUserPolicyAttachment' = do
      result <- liftIO $ runExceptT $ createUserPolicyAttachment db uid pid
      case result of
        Right attachment -> return attachment
        Left err         -> errorHandler err


deleteUserPolicyAttachmentHandler :: DB db =>
  db -> Auth -> UserIdentifier -> UUID -> Handler UserPolicyAttachment
deleteUserPolicyAttachmentHandler db auth uid pid = do
  requireSession auth
  result <- liftIO $ runExceptT $ deleteUserPolicyAttachment db uid pid
  case result of
    Right attachment -> return attachment
    Left err         -> errorHandler err


createGroupPolicyAttachmentHandler :: DB db =>
  db -> Auth -> GroupIdentifier -> UUID -> Handler GroupPolicyAttachment
createGroupPolicyAttachmentHandler db auth gid pid = do
  requireSession auth
  result <- liftIO $ runExceptT $ getPolicy db pid
  case result of
    Right policy -> do
      if policy `isAllowedBy` policyRules callerPolicies
        then createGroupPolicyAttachment'
        else throwError err403
    Left err -> errorHandler err
  where
    callerPolicies = authPolicies $ authorization auth
    createGroupPolicyAttachment' = do
      result <- liftIO $ runExceptT $ createGroupPolicyAttachment db gid pid
      case result of
        Right attachment -> return attachment
        Left err         -> errorHandler err


deleteGroupPolicyAttachmentHandler :: DB db =>
  db -> Auth -> GroupIdentifier -> UUID -> Handler GroupPolicyAttachment
deleteGroupPolicyAttachmentHandler db auth gid pid = do
  requireSession auth
  result <- liftIO $ runExceptT $ deleteGroupPolicyAttachment db gid pid
  case result of
    Right attachment -> return attachment
    Left err         -> errorHandler err


createSessionHandler :: DB db => db -> Auth -> UserIdentifier -> Handler CreateSession
createSessionHandler db _ uid = do
  r0 <- liftIO $ runExceptT $ getUserId db uid
  case r0 of
    Left e -> throwError $ toServerError e
    Right uid' -> do
      result <- liftIO $ runExceptT $ IAM.Server.DB.createSession db uid'
      case result of
        Right session' -> return session'
        Left err       -> errorHandler err


listUserSessionsHandler :: DB db =>
  db -> Auth -> UserIdentifier -> Maybe Int -> Maybe Int -> Handler [Session]
listUserSessionsHandler db auth uid maybeOffset maybeLimit = do
  requireSession auth
  let offset = fromMaybe 0 maybeOffset
  result <- liftIO $ runExceptT $ listUserSessions db uid $ Range offset maybeLimit
  case result of
    Right sessions -> return sessions
    Left err       -> errorHandler err


getUserSessionHandler :: DB db =>
  db -> Auth -> UserIdentifier -> SessionId -> Handler Session
getUserSessionHandler db auth uid sid = do
  requireSession auth
  result <- liftIO $ runExceptT $ getSessionById db uid sid
  case result of
    Right session -> return session
    Left err      -> errorHandler err


deleteUserSessionHandler :: DB db =>
  db -> Auth -> UserIdentifier -> SessionId -> Handler Session
deleteUserSessionHandler db auth uid sid = do
  requireSession auth
  result <- liftIO $ runExceptT $ deleteSession db uid sid
  case result of
    Right session -> return session
    Left err      -> errorHandler err


refreshUserSessionHandler :: DB db =>
  db -> Auth -> UserIdentifier -> SessionId -> Handler Session
refreshUserSessionHandler db auth uid sid = do
  requireSession auth
  result' <- liftIO $ runExceptT $ IAM.Server.DB.refreshSession db uid sid
  case result' of
    Right session' -> return session'
    Left err       -> errorHandler err


authorizeHandler :: DB db =>
  db ->  AuthorizationRequest -> Handler AuthorizationResponse
authorizeHandler db req = do
  r0 <- liftIO $ runExceptT $ getUserId db userIdent
  uid <- case r0 of
    Left e -> throwError $ toServerError e
    Right uid' -> return uid'

  let host = authorizationRequestHost req
  result <- liftIO $ runExceptT $ listPoliciesForUser db uid host
  case result of
    Left err -> errorHandler err
    Right policies ->
      return $ AuthorizationResponse $
        if isAuthorized reqAction reqResource $ policyRules policies
          then Allow
          else Deny

  where

  userIdent = authorizationRequestUser req
  reqAction = authorizationRequestAction req
  reqResource = authorizationRequestResource req


requireSession :: Auth -> Handler ()
requireSession auth = do
  case authSession $ authorization auth of
    Just Session{} -> return ()
    Nothing        -> throwError $ err401 { errBody = "Session required" }
