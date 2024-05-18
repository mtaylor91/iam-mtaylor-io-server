{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Handlers
  ( module IAM.Server.Handlers
  ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.Maybe
import Data.Text
import Servant

import IAM.Authorization
import IAM.Error
import IAM.Group
import IAM.GroupPolicy
import IAM.GroupIdentifier
import IAM.Identifier
import IAM.Ip
import IAM.ListResponse
import IAM.Login
import IAM.Membership
import IAM.Policy
import IAM.PublicKey
import IAM.Range
import IAM.Server.Auth
import IAM.Server.Context
import IAM.Server.DB
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserIdentifier
import IAM.UserPolicy
import IAM.UserPublicKey


loginRequestHandler :: DB db => Ctx db -> Auth -> LoginRequest ->
  Handler (LoginResponse CreateSession)
loginRequestHandler ctx auth req = do
  -- Check if the login request already exists
  let lid = loginRequestId req
  let uid = loginRequestUser req
  lrResult <- liftIO $ runExceptT $ getLoginResponse (ctxDB ctx) uid lid
  case lrResult of
    Right r -> ret r -- Return the existing login request
    Left (NotFound (LoginIdentifier lid')) | lid == lid' -> do
      -- Look up the user ID
      uidResult <- liftIO $ runExceptT $ getUserId (ctxDB ctx) (loginRequestUser req)
      -- Look up the IP address
      let maybeAddr = fromSockAddr $ authAddr auth
      case (uidResult, maybeAddr) of
        (Left err, _) -> errorHandler err
        (_, Nothing) -> errorHandler $ InternalError "Invalid address"
        (Right uid', Just ip) -> do
          -- Create the login request
          resp <- liftIO $ createLoginRequest req ip uid'
          result <- liftIO $ runExceptT $ createLoginResponse (ctxDB ctx) resp
          case result of
            Right resp' -> ret resp'
            Left err    -> errorHandler err
    Left err -> errorHandler err

  where

    ret :: LoginResponse SessionId -> Handler (LoginResponse CreateSession)
    ret resp = case (loginResponseStatus resp, loginResponseSession resp) of
      (LoginRequestGranted, Nothing) -> do
        -- Create a session
        let ip = loginResponseIp resp
        let uid = loginResponseUserId resp
        s <- liftIO $ runExceptT $ IAM.Server.DB.createSession (ctxDB ctx) ip uid
        case s of
          Left err -> errorHandler err
          Right s' -> do
            -- Update the login request with the session ID
            let f r = r { loginResponseSession = Just (createSessionId s') }
            result <- liftIO $ runExceptT $ updateLoginResponse (ctxDB ctx)
              (UserIdentifier (Just uid) Nothing Nothing) (loginResponseRequest resp) f
            case result of
              Left err -> errorHandler err
              -- Return the updated login request
              Right _ -> return $ resp { loginResponseSession = Just s' }
      (_, _) -> return $ resp { loginResponseSession = Nothing }


listLoginRequestsHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> Maybe Int -> Maybe Int ->
    Handler (ListResponse (LoginResponse SessionId))
listLoginRequestsHandler ctx auth uid maybeOffset maybeLimit = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ listLoginResponses (ctxDB ctx) uid range
  case result of
    Right loginRequests -> return loginRequests
    Left err            -> errorHandler err
  where
    range = Range offset' maybeLimit
    offset' = fromMaybe 0 maybeOffset


getLoginRequestHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> LoginRequestId -> Handler (LoginResponse SessionId)
getLoginRequestHandler ctx auth uid lrid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ getLoginResponse (ctxDB ctx) uid lrid
  case result of
    Right resp -> return resp
    Left err   -> errorHandler err


deleteLoginRequestHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> LoginRequestId -> Handler (LoginResponse SessionId)
deleteLoginRequestHandler ctx auth uid lrid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteLoginResponse (ctxDB ctx) uid lrid
  case result of
    Right resp -> return resp
    Left err   -> errorHandler err


updateLoginRequestHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> LoginRequestId -> LoginStatus ->
    Handler (LoginResponse SessionId)
updateLoginRequestHandler ctx auth uid lrid status = do
  _ <- requireSession auth
  result0 <- liftIO $ runExceptT $ updateLoginResponse (ctxDB ctx) uid lrid f
  case result0 of
    Left err -> errorHandler err
    Right resp -> case status of
      LoginRequestGranted -> do
        -- Associate the login key with the user
        let key = loginResponsePublicKey resp
        let uid' = loginResponseUserId resp
        let dbOp = upsertUserPublicKey (ctxDB ctx) uid' key
        result1 <- liftIO $ runExceptT dbOp
        case result1 of
          Left err -> errorHandler err
          Right _  -> return resp
      _ -> return resp
  where
    f resp = resp { loginResponseStatus = status }


createUserPublicKeyHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> UserPublicKey -> Handler UserPublicKey
createUserPublicKeyHandler ctx auth uid key = do
  _ <- requireSession auth
  r0 <- liftIO $ runExceptT $ getUserId (ctxDB ctx) uid
  case r0 of
    Left e -> errorHandler e
    Right uid' -> do
      result <- liftIO $ runExceptT $ upsertUserPublicKey (ctxDB ctx) uid' key
      case result of
        Right key' -> return key'
        Left err   -> errorHandler err


listUserPublicKeysHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> Maybe Int -> Maybe Int ->
    Handler (ListResponse UserPublicKey)
listUserPublicKeysHandler ctx auth uid maybeOffset maybeLimit = do
  _ <- requireSession auth
  r0 <- liftIO $ runExceptT $ getUserId (ctxDB ctx) uid
  case r0 of
    Left e -> errorHandler e
    Right uid' -> do
      let range = Range offset' maybeLimit
      result <- liftIO $ runExceptT $ listUserPublicKeys (ctxDB ctx) uid' range
      case result of
        Right keys -> return keys
        Left err   -> errorHandler err
  where
    offset' = fromMaybe 0 maybeOffset


getUserPublicKeyHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> PublicKey' -> Handler UserPublicKey
getUserPublicKeyHandler ctx auth uid (PublicKey' key) = do
  _ <- requireSession auth
  r0 <- liftIO $ runExceptT $ getUserId (ctxDB ctx) uid
  case r0 of
    Left e -> errorHandler e
    Right uid' -> do
      result <- liftIO $ runExceptT $ getUserPublicKey (ctxDB ctx) uid' key
      case result of
        Right key' -> return key'
        Left err   -> errorHandler err


deleteUserPublicKeyHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> PublicKey' -> Handler UserPublicKey
deleteUserPublicKeyHandler ctx auth uid (PublicKey' key) = do
  _ <- requireSession auth
  r0 <- liftIO $ runExceptT $ getUserId (ctxDB ctx) uid
  case r0 of
    Left e -> errorHandler e
    Right uid' -> do
      result <- liftIO $ runExceptT $ deleteUserPublicKey (ctxDB ctx) uid' key
      case result of
        Right key' -> return key'
        Left err   -> errorHandler err


getUserHandler :: DB db => Ctx db -> Auth -> UserIdentifier -> Handler User
getUserHandler ctx auth uid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ getUser (ctxDB ctx) uid
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


listUsersHandler ::
  DB db => Ctx db -> Auth -> Maybe Text -> Maybe SortUsersBy -> Maybe SortOrder ->
    Maybe Int -> Maybe Int -> Handler (ListResponse UserIdentifier)
listUsersHandler ctx auth Nothing maybeSort maybeOrder maybeOffset maybeLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 maybeOffset
  result <- liftIO $ runExceptT $ listUsers (ctxDB ctx) (Range offset' maybeLimit)
    (fromMaybe SortUsersByEmail maybeSort) (fromMaybe Ascending maybeOrder)
  case result of
    Right users' -> return users'
    Left err     -> errorHandler err
listUsersHandler ctx auth (Just search) maybeSort maybeOrder maybeOffset maybeLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 maybeOffset
  result <- liftIO $ runExceptT $ listUsersBySearchTerm (ctxDB ctx) search
    (Range offset' maybeLimit) (fromMaybe SortUsersByEmail maybeSort)
    (fromMaybe Ascending maybeOrder)
  case result of
    Right users' -> return users'
    Left err     -> errorHandler err


createUserHandler :: DB db => Ctx db -> Auth -> User -> Handler User
createUserHandler ctx auth userPrincipal = do
  case validateUser userPrincipal of
    Left err -> errorHandler err
    Right _  -> return ()
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ createUser (ctxDB ctx) userPrincipal
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


updateUserHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> UserUpdate -> Handler User
updateUserHandler ctx auth uid userUpdate = do
  _ <- requireSession auth
  case validateUserUpdate userUpdate of
    Left err -> errorHandler err
    Right _  -> return ()
  result <- liftIO $ runExceptT $ updateUser (ctxDB ctx) uid userUpdate
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


deleteUserHandler :: DB db => Ctx db -> Auth -> UserIdentifier -> Handler User
deleteUserHandler ctx auth uid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteUser (ctxDB ctx) uid
  case result of
    Right user' -> return user'
    Left err    -> errorHandler err


getGroupHandler :: DB db => Ctx db -> Auth -> GroupIdentifier -> Handler Group
getGroupHandler ctx auth gid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ getGroup (ctxDB ctx) gid
  case result of
    Right group' -> return group'
    Left err     -> errorHandler err


listGroupsHandler :: DB db =>
  Ctx db -> Auth -> Maybe Text -> Maybe SortGroupsBy -> Maybe SortOrder ->
    Maybe Int -> Maybe Int -> Handler (ListResponse GroupIdentifier)
listGroupsHandler ctx auth Nothing sort order maybeOffset maybeLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 maybeOffset
      sort' = fromMaybe SortGroupsByName sort
      order' = fromMaybe Ascending order
  result <- liftIO $ runExceptT $
    listGroups (ctxDB ctx) (Range offset' maybeLimit) sort' order'
  case result of
    Right groups' -> return groups'
    Left err      -> errorHandler err
listGroupsHandler ctx auth (Just search) sort order maybeOffset maybeLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 maybeOffset
      sort' = fromMaybe SortGroupsByName sort
      order' = fromMaybe Ascending order
  result <- liftIO $ runExceptT $ listGroupsBySearchTerm (ctxDB ctx) search
    (Range offset' maybeLimit) sort' order'
  case result of
    Right groups' -> return groups'
    Left err      -> errorHandler err


createGroupHandler :: DB db => Ctx db -> Auth -> Group -> Handler Group
createGroupHandler ctx auth group' = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ createGroup (ctxDB ctx) group'
  case result of
    Right group'' -> return group''
    Left err -> errorHandler err


deleteGroupHandler :: DB db => Ctx db -> Auth -> GroupIdentifier -> Handler Group
deleteGroupHandler ctx auth gid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteGroup (ctxDB ctx) gid
  case result of
    Right g -> return g
    Left err -> errorHandler err


getPolicyHandler :: DB db => Ctx db -> Auth -> PolicyIdentifier -> Handler Policy
getPolicyHandler ctx auth policy = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ getPolicy (ctxDB ctx) policy
  case result of
    Right policy' -> return policy'
    Left err      -> errorHandler err


listPoliciesHandler ::
  DB db => Ctx db -> Auth -> Maybe Text -> Maybe SortPoliciesBy -> Maybe SortOrder ->
    Maybe Int -> Maybe Int -> Handler (ListResponse PolicyIdentifier)
listPoliciesHandler ctx auth Nothing mSort mOrder mOffset mLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 mOffset
  let sort' = fromMaybe SortPoliciesByName mSort
  let order' = fromMaybe Ascending mOrder
  let dbOp = listPolicyIds (ctxDB ctx) (Range offset' mLimit) sort' order'
  result <- liftIO $ runExceptT dbOp
  case result of
    Right pids -> return pids
    Left err   -> errorHandler err
listPoliciesHandler ctx auth (Just search) mSort mOrder mOffset mLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 mOffset
  let sort' = fromMaybe SortPoliciesByName mSort
  let order' = fromMaybe Ascending mOrder
  let range = Range offset' mLimit
  let dbOp = listPolicyIdsBySearchTerm (ctxDB ctx) search range sort' order'
  result <- liftIO $ runExceptT dbOp
  case result of
    Right pids -> return pids
    Left err   -> errorHandler err


createPolicyHandler :: DB db => Ctx db -> Auth -> Policy -> Handler Policy
createPolicyHandler ctx auth policy = do
  _ <- requireSession auth
  authZ' <- requireAuthorization auth
  let callerPolicies = authPolicies authZ'
  if policy `isAllowedBy` policyRules callerPolicies
    then createPolicy'
    else errorHandler NotAuthorized
  where
    createPolicy' = do
      result <- liftIO $ runExceptT $ createPolicy (ctxDB ctx) policy
      case result of
        Right policy' -> return policy'
        Left err      -> errorHandler err


deletePolicyHandler :: DB db => Ctx db -> Auth -> PolicyIdentifier -> Handler Policy
deletePolicyHandler ctx auth policy = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deletePolicy (ctxDB ctx) policy
  case result of
    Right policy' -> return policy'
    Left err      -> errorHandler err


getMembershipHandler :: DB db =>
  Ctx db -> Auth -> GroupIdentifier -> UserIdentifier -> Handler NoContent
getMembershipHandler ctx auth gid uid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ getMembership (ctxDB ctx) uid gid
  case result of
    Right _ -> return NoContent
    Left err -> errorHandler err


createMembershipHandler ::
  DB db => Ctx db -> Auth -> GroupIdentifier -> UserIdentifier -> Handler Membership
createMembershipHandler ctx auth gid uid = do
  _ <- requireSession auth
  -- Check if the user is allowed to create the membership
  authZ' <- requireAuthorization auth
  let callerPolicies = authPolicies authZ'
  result0 <- liftIO $ runExceptT $ getGroup (ctxDB ctx) gid
  case result0 of
    Left err -> errorHandler err
    Right grp -> do
      policies <- fetchPolicies $ groupPolicies grp
      if Prelude.all (`isAllowedBy` policyRules callerPolicies) policies
        then createMembership'
        else errorHandler NotAuthorized
  where
    createMembership' :: Handler Membership
    createMembership' = do
      result <- liftIO $ runExceptT $ createMembership (ctxDB ctx) uid gid
      case result of
        Right membership -> return membership
        Left err         -> errorHandler err
    fetchPolicies :: [PolicyIdentifier] -> Handler [Policy]
    fetchPolicies [] = return []
    fetchPolicies (pid:pids) = do
      result <- liftIO $ runExceptT $ getPolicy (ctxDB ctx) pid
      case result of
        Left err -> errorHandler err
        Right policy -> do
          policies <- fetchPolicies pids
          return $ policy:policies


deleteMembershipHandler ::
  DB db => Ctx db -> Auth -> GroupIdentifier -> UserIdentifier -> Handler Membership
deleteMembershipHandler ctx auth gid uid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteMembership (ctxDB ctx) uid gid
  case result of
    Right membership -> return membership
    Left err         -> errorHandler err


createUserPolicyAttachmentHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> PolicyIdentifier -> Handler UserPolicyAttachment
createUserPolicyAttachmentHandler ctx auth uid pid = do
  _ <- requireSession auth
  authZ' <- requireAuthorization auth
  result0 <- liftIO $ runExceptT $ getPolicy (ctxDB ctx) pid
  case result0 of
    Right policy -> do
      if policy `isAllowedBy` policyRules (authPolicies authZ')
        then createUserPolicyAttachment'
        else errorHandler NotAuthorized
    Left err -> errorHandler err
  where
    createUserPolicyAttachment' = do
      result <- liftIO $ runExceptT $ createUserPolicyAttachment (ctxDB ctx) uid pid
      case result of
        Right attachment -> return attachment
        Left err         -> errorHandler err


deleteUserPolicyAttachmentHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> PolicyIdentifier -> Handler UserPolicyAttachment
deleteUserPolicyAttachmentHandler ctx auth uid pid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteUserPolicyAttachment (ctxDB ctx) uid pid
  case result of
    Right attachment -> return attachment
    Left err         -> errorHandler err


createGroupPolicyAttachmentHandler :: DB db =>
  Ctx db -> Auth -> GroupIdentifier -> PolicyIdentifier -> Handler GroupPolicyAttachment
createGroupPolicyAttachmentHandler ctx auth gid pid = do
  _ <- requireSession auth
  authZ' <- requireAuthorization auth
  result <- liftIO $ runExceptT $ getPolicy (ctxDB ctx) pid
  case result of
    Right policy -> do
      if policy `isAllowedBy` policyRules (authPolicies authZ')
        then createGroupPolicyAttachment'
        else errorHandler NotAuthorized
    Left err -> errorHandler err
  where
    createGroupPolicyAttachment' = do
      result <- liftIO $ runExceptT $ createGroupPolicyAttachment (ctxDB ctx) gid pid
      case result of
        Right attachment -> return attachment
        Left err         -> errorHandler err


deleteGroupPolicyAttachmentHandler :: DB db =>
  Ctx db -> Auth -> GroupIdentifier -> PolicyIdentifier -> Handler GroupPolicyAttachment
deleteGroupPolicyAttachmentHandler ctx auth gid pid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteGroupPolicyAttachment (ctxDB ctx) gid pid
  case result of
    Right attachment -> return attachment
    Left err         -> errorHandler err


createSessionHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> Handler CreateSession
createSessionHandler ctx auth uid = do
  _ <- requireAuthentication auth
  r0 <- liftIO $ runExceptT $ getUserId (ctxDB ctx) uid
  case r0 of
    Left e -> errorHandler e
    Right uid' -> do
      case fromSockAddr $ authAddr auth of
        Nothing -> errorHandler $ InternalError "Invalid address"
        Just addr -> do
          let dbOp = IAM.Server.DB.createSession (ctxDB ctx) addr uid'
          result <- liftIO $ runExceptT dbOp
          case result of
            Right session' -> return session'
            Left err       -> errorHandler err


listUserSessionsHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> Maybe Int -> Maybe Int ->
    Handler (ListResponse Session)
listUserSessionsHandler ctx auth uid maybeOffset maybeLimit = do
  _ <- requireSession auth
  let offset' = fromMaybe 0 maybeOffset
  let dbOp = listUserSessions (ctxDB ctx) uid $ Range offset' maybeLimit
  result <- liftIO $ runExceptT dbOp
  case result of
    Right sessions -> return sessions
    Left err       -> errorHandler err


getUserSessionHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> SessionId -> Handler Session
getUserSessionHandler ctx auth uid sid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ getSessionById (ctxDB ctx) uid sid
  case result of
    Right session -> return session
    Left err      -> errorHandler err


deleteUserSessionHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> SessionId -> Handler Session
deleteUserSessionHandler ctx auth uid sid = do
  _ <- requireSession auth
  result <- liftIO $ runExceptT $ deleteSession (ctxDB ctx) uid sid
  case result of
    Right session -> return session
    Left err      -> errorHandler err


refreshUserSessionHandler :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> SessionId -> Handler Session
refreshUserSessionHandler ctx auth uid sid = do
  _ <- requireSession auth
  result' <- liftIO $ runExceptT $ IAM.Server.DB.refreshSession (ctxDB ctx) uid sid
  case result' of
    Right session' -> return session'
    Left err       -> errorHandler err


authorizeHandler :: DB db =>
  Ctx db ->  AuthorizationRequest -> Handler AuthorizationResponse
authorizeHandler ctx req = do
  r0 <- liftIO $ runExceptT $ getUserId (ctxDB ctx) userIdent
  uid <- case r0 of
    Left e -> errorHandler e
    Right uid' -> return uid'

  case mToken of
    Nothing -> return ()
    Just token -> do
      result <- liftIO $ runExceptT $ getSessionByToken (ctxDB ctx) userIdent token
      case result of
        Left err -> errorHandler err
        Right _  -> return ()

  let host = authorizationRequestHost req
  result <- liftIO $ runExceptT $ listPoliciesForUser (ctxDB ctx) uid host
  case result of
    Left err -> errorHandler err
    Right policies ->
      return $ AuthorizationResponse $
        if isAuthorized reqAction reqResource $ policyRules policies
          then Allow
          else Deny

  where

  mToken = authorizationRequestToken req
  userIdent = authorizationRequestUser req
  reqAction = authorizationRequestAction req
  reqResource = authorizationRequestResource req


requireAuthentication :: Auth -> Handler Authentication
requireAuthentication auth = do
  case authN auth of
    Just authN' -> return authN'
    Nothing     -> errorHandler $ AuthenticationFailed AuthenticationRequired


requireAuthorization :: Auth -> Handler Authorization
requireAuthorization auth = do
  case authZ auth of
    Just authZ' -> return authZ'
    Nothing     -> errorHandler $ AuthenticationFailed AuthenticationRequired


requireSession :: Auth -> Handler Session
requireSession auth = do
  authZ' <- requireAuthorization auth
  case authSession authZ' of
    Just s  -> return s
    Nothing -> errorHandler $ AuthenticationFailed SessionRequired
