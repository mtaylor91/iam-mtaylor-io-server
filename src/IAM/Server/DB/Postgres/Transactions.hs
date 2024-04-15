module IAM.Server.DB.Postgres.Transactions
  ( module IAM.Server.DB.Postgres.Transactions
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.Aeson (Result(..), fromJSON, toJSON)
import Data.Maybe
import Data.Text (Text, pack)
import Data.UUID (UUID)
import Data.Vector (toList)
import Hasql.Transaction (Transaction, statement)

import IAM.Error
import IAM.Group
import IAM.GroupPolicy
import IAM.Identifiers
import IAM.Policy
import IAM.Membership
import IAM.Server.DB.Postgres.Queries
import IAM.Range
import IAM.Session
import IAM.User
import IAM.UserPolicy


pgGetUser :: UserIdentifier -> Transaction (Either Error User)
pgGetUser userIdentifier =
  case unUserIdentifier userIdentifier of
    Left email -> pgGetUserByEmail email
    Right (UserUUID uuid) -> pgGetUserById $ UserUUID uuid


pgGetUserByEmail :: Text -> Transaction (Either Error User)
pgGetUserByEmail email = do
  result0 <- statement email selectUserIdByEmail
  case result0 of
    Nothing -> return $ Left $ NotFound $ UserNotFound $ UserEmail email
    Just uuid' -> do
      pgGetUser (UserId $ UserUUID uuid')


pgGetUserById :: UserId -> Transaction (Either Error User)
pgGetUserById (UserUUID uuid) = do
  result <- statement uuid selectUserId
  case result of
    Nothing -> return $ Left $ NotFound $ UserNotFound $ UserId $ UserUUID uuid
    Just _ -> do
      maybeEmail <- statement uuid selectUserEmail
      r0 <- statement uuid selectUserGroups
      r1 <- statement uuid selectUserPolicyIdentifiers
      r2 <- statement uuid selectUserPublicKeys
      let groups = map group $ toList r0
      let publicKeys = map pk $ toList r2
      let policies = map pid $ toList r1
      return $ Right $ User (UserUUID uuid) maybeEmail groups policies publicKeys
  where
    group (guuid, Nothing) = GroupId $ GroupUUID guuid
    group (guuid, Just name) = GroupIdAndName (GroupUUID guuid) name
    pid (pid', Nothing) = PolicyId $ PolicyUUID pid'
    pid (pid', Just name) = PolicyIdAndName (PolicyUUID pid') name
    pk (pkBytes, pkDescription) = UserPublicKey (PublicKey pkBytes) pkDescription


pgGetUserId :: UserIdentifier -> Transaction (Either Error UserId)
pgGetUserId userIdentifier = do
  case unUserIdentifier userIdentifier of
    Left email -> do
      result <- statement email selectUserIdByEmail
      case result of
        Nothing -> return $ Left $ NotFound $ UserNotFound userIdentifier
        Just uuid' -> return $ Right $ UserUUID uuid'
    Right (UserUUID uuid) -> return $ Right $ UserUUID uuid


pgListUsers :: Range -> Transaction (Either Error [UserIdentifier])
pgListUsers (Range offset Nothing) = pgListUsers (Range offset $ Just 100)
pgListUsers (Range offset (Just limit)) = do
  result <- statement (fromIntegral offset, fromIntegral limit) selectUserIdentifiers
  return $ Right $ map userIdentifier $ toList result
  where
    userIdentifier (uuuid, Nothing) = UserId $ UserUUID uuuid
    userIdentifier (uuuid, Just email) = UserIdAndEmail (UserUUID uuuid) email
          


pgCreateUser :: User -> Transaction (Either Error User)
pgCreateUser (User (UserUUID uuid) maybeEmail groups policies publicKeys) = do
  result0 <- statement uuid selectUserId
  result1 <- emailQuery maybeEmail

  case (result0, result1) of
    (Just _, _) -> return $ Left AlreadyExists
    (_, Just _) -> return $ Left AlreadyExists
    (Nothing, Nothing) -> do
      statement uuid insertUserId

      case maybeEmail of
        Nothing -> return ()
        Just email -> do
          statement (uuid, email) insertUserEmail

      result2 <- resolveUserGroups groups
      case result2 of
        Left e -> return $ Left e
        Right gids -> do

          result3 <- resolvePolicies policies
          case result3 of
            Left e -> return $ Left e
            Right pids -> do
              mapM_ insertUserGroup' gids
              mapM_ insertUserPolicy' $ fmap unPolicyId pids
              mapM_ insertUserPublicKey' publicKeys

              return $ Right $ User (UserUUID uuid) maybeEmail groups policies publicKeys

  where

  emailQuery :: Maybe Text -> Transaction (Maybe UUID)
  emailQuery Nothing = return Nothing
  emailQuery (Just email) = do
    result <- statement email selectUserIdByEmail
    case result of
      Nothing -> return Nothing
      Just uuuid -> return $ Just uuuid

  insertUserGroup' :: GroupId -> Transaction ()
  insertUserGroup' (GroupUUID guuid) = statement (uuid, guuid) insertUserGroup

  insertUserPolicy' :: UUID -> Transaction ()
  insertUserPolicy' pid = statement (uuid, pid) insertUserPolicy

  insertUserPublicKey' :: UserPublicKey -> Transaction ()
  insertUserPublicKey' (UserPublicKey (PublicKey pk) description) =
    statement (uuid, pk, description) insertUserPublicKey


pgDeleteUser :: UserIdentifier -> Transaction (Either Error User)
pgDeleteUser userIdentifier = do
  case unUserIdentifier userIdentifier of
    Left email -> pgDeleteUserByEmail email
    Right (UserUUID uuid) -> pgDeleteUserById $ UserUUID uuid


pgDeleteUserByEmail :: Text -> Transaction (Either Error User)
pgDeleteUserByEmail email = do
  result0 <- statement email selectUserIdByEmail
  case result0 of
    Nothing -> return $ Left $ NotFound $ UserNotFound $ UserEmail email
    Just uuid' -> pgDeleteUserById $ UserUUID uuid'


pgDeleteUserById :: UserId -> Transaction (Either Error User)
pgDeleteUserById (UserUUID uuid) = do
  result <- pgGetUserById $ UserUUID uuid
  case result of
    Left e -> return $ Left e
    Right user -> do
      statement uuid deleteUserPublicKeys
      statement uuid deleteUserPolicies
      statement uuid deleteUserGroups
      statement uuid deleteUserEmail
      statement uuid deleteUserId
      return $ Right user


pgGetGroup :: GroupIdentifier -> Transaction (Either Error Group)
pgGetGroup groupIdentifier =
  case unGroupIdentifier groupIdentifier of
    Left name -> pgGetGroupByName name
    Right (GroupUUID uuid) -> pgGetGroupById $ GroupUUID uuid


pgGetGroupByName :: Text -> Transaction (Either Error Group)
pgGetGroupByName name = do
  result0 <- statement name selectGroupIdByName
  case result0 of
    Nothing -> return $ Left $ NotFound $ GroupNotFound $ GroupName name
    Just uuid' -> pgGetGroupById $ GroupUUID uuid'


pgGetGroupById :: GroupId -> Transaction (Either Error Group)
pgGetGroupById (GroupUUID uuid) = do
  result <- statement uuid selectGroupId
  case result of
    Nothing -> return $ Left $ NotFound $ GroupNotFound $ GroupId $ GroupUUID uuid
    Just _ -> do
      maybeName <- statement uuid selectGroupName
      r0 <- statement uuid selectGroupUsers
      r1 <- statement uuid selectGroupPolicyIdentifiers
      let users = map user $ toList r0
      let policies = map pid $ toList r1
      return $ Right $ Group (GroupUUID uuid) maybeName users policies
  where
    user (uuuid, Nothing) = UserId $ UserUUID uuuid
    user (uuuid, Just email) = UserIdAndEmail (UserUUID uuuid) email
    pid (pid', Nothing) = PolicyId $ PolicyUUID pid'
    pid (pid', Just name) = PolicyIdAndName (PolicyUUID pid') name


pgListGroups :: Range -> Transaction (Either Error [GroupIdentifier])
pgListGroups (Range offset maybeLimit) = do
  let limit = fromMaybe 100 maybeLimit
  result <- statement (fromIntegral offset, fromIntegral limit) selectGroupIdentifiers
  return $ Right $ map groupIdentifier $ toList result
  where
    groupIdentifier (guuid, Nothing) = GroupId $ GroupUUID guuid
    groupIdentifier (guuid, Just name) = GroupIdAndName (GroupUUID guuid) name


pgCreateGroup :: Group -> Transaction (Either Error Group)
pgCreateGroup (Group (GroupUUID uuid) maybeName users policies) = do
  result0 <- statement uuid selectGroupId
  result1 <- nameQuery maybeName
  case (result0, result1) of
    (Just _, _) -> return $ Left AlreadyExists
    (_, Just _) -> return $ Left AlreadyExists
    (Nothing, Nothing) -> do
      statement uuid insertGroupId

      case maybeName of
        Nothing -> return ()
        Just name -> do
          statement (uuid, name) insertGroupName

      result2 <- resolveGroupUsers users
      case result2 of
        Left e -> return $ Left e
        Right uids -> do

          result3 <- resolvePolicies policies
          case result3 of
            Left e -> return $ Left e
            Right pids -> do
              mapM_ insertGroupUser' uids
              mapM_ insertGroupPolicy' pids
              return $ Right $ Group (GroupUUID uuid) maybeName users policies

  where

  nameQuery :: Maybe Text -> Transaction (Maybe UUID)
  nameQuery Nothing = return Nothing
  nameQuery (Just name) = do
    result <- statement name selectGroupIdByName
    case result of
      Nothing -> return Nothing
      Just guuid -> return $ Just guuid

  insertGroupUser' :: UserId -> Transaction ()
  insertGroupUser' (UserUUID uuuid) = statement (uuid, uuuid) insertGroupUser

  insertGroupPolicy' :: PolicyId -> Transaction ()
  insertGroupPolicy' (PolicyUUID pid) = statement (uuid, pid) insertGroupPolicy

  resolveGroupUsers :: [UserIdentifier] -> Transaction (Either Error [UserId])
  resolveGroupUsers [] = return $ Right []
  resolveGroupUsers (uident:rest) = do
    result <- resolveUserIdentifier uident
    case result of
      Nothing ->
        return $ Left $ NotFound $ UserNotFound uident
      Just (UserUUID uuuid) -> do
        result' <- resolveGroupUsers rest
        case result' of
          Left e -> return $ Left e
          Right uids -> return $ Right $ UserUUID uuuid : uids


pgDeleteGroup :: GroupIdentifier -> Transaction (Either Error Group)
pgDeleteGroup groupIdentifier = do
  case unGroupIdentifier groupIdentifier of
    Left name -> pgDeleteGroupByName name
    Right (GroupUUID uuid) -> pgDeleteGroupById $ GroupUUID uuid


pgDeleteGroupByName :: Text -> Transaction (Either Error Group)
pgDeleteGroupByName name = do
  result0 <- statement name selectGroupIdByName
  case result0 of
    Nothing -> return $ Left $ NotFound $ GroupNotFound $ GroupName name
    Just uuid' -> pgDeleteGroupById $ GroupUUID uuid'


pgDeleteGroupById :: GroupId -> Transaction (Either Error Group)
pgDeleteGroupById (GroupUUID uuid) = do
  result <- pgGetGroupById $ GroupUUID uuid
  case result of
    Left e -> return $ Left e
    Right group -> do
      statement uuid deleteGroupPolicies
      statement uuid deleteGroupUsers
      statement uuid deleteGroupName
      statement uuid deleteGroupId
      return $ Right group


pgGetPolicy :: PolicyIdentifier -> Transaction (Either Error Policy)
pgGetPolicy (PolicyId (PolicyUUID pid)) = do
  result <- statement pid selectPolicy
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyId $ PolicyUUID pid
    Just policy ->
      case fromJSON policy of
        Error e -> return $ Left $ InternalError $ pack $ show e
        Success p -> return $ Right p
pgGetPolicy (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyName name
    Just pid -> pgGetPolicy $ PolicyId $ PolicyUUID pid
pgGetPolicy (PolicyIdAndName (PolicyUUID pid) _) =
  pgGetPolicy $ PolicyId $ PolicyUUID pid


pgListPolicies :: Range -> Transaction (Either Error [PolicyIdentifier])
pgListPolicies (Range offset maybeLimit) = do
  let limit = fromMaybe 100 maybeLimit
  result <- statement (fromIntegral offset, fromIntegral limit) selectPolicyIdentifiers
  return $ Right $ map policyIdentifier $ toList result
  where
    policyIdentifier (pid, Nothing) = PolicyId $ PolicyUUID pid
    policyIdentifier (pid, Just name) = PolicyIdAndName (PolicyUUID pid) name


pgListPoliciesForUser :: Text -> UserId -> Transaction (Either Error [Policy])
pgListPoliciesForUser host (UserUUID uuid) = do
  r0 <- statement (uuid, host) selectUserPoliciesForHost
  r1 <- statement uuid selectUserGroups
  let groups = map group $ toList r1
  case mapM fromJSON $ toList r0 of
    Error e -> return $ Left $ InternalError $ pack $ show e
    Success ups -> do
      r2 <- mapM (pgListPoliciesForGroup host) groups
      case sequence r2 of
        Left e -> return $ Left e
        Right gps -> return $ Right $ ups ++ concat gps
  where
    group (guuid, _) = GroupId $ GroupUUID guuid


pgListPoliciesForGroup ::
  Text -> GroupIdentifier -> Transaction (Either Error [Policy])
pgListPoliciesForGroup host groupIdentifier = do
  case unGroupIdentifier groupIdentifier of
    Left name -> pgListPoliciesForGroupByName host name
    Right (GroupUUID uuid) -> pgListPoliciesForGroupById host $ GroupUUID uuid


pgListPoliciesForGroupByName :: Text -> Text -> Transaction (Either Error [Policy])
pgListPoliciesForGroupByName host name = do
  result0 <- statement name selectGroupIdByName
  case result0 of
    Nothing -> return $ Left $ NotFound $ GroupNotFound $ GroupName name
    Just uuid' -> pgListPoliciesForGroupById host $ GroupUUID uuid'


pgListPoliciesForGroupById :: Text -> GroupId -> Transaction (Either Error [Policy])
pgListPoliciesForGroupById host (GroupUUID uuid) = do
  r0 <- statement (uuid, host) selectGroupPoliciesForHost
  case mapM fromJSON $ toList r0 of
    Error e -> return $ Left $ InternalError $ pack $ show e
    Success policies -> return $ Right policies


pgCreatePolicy :: Policy -> Transaction (Either Error Policy)
pgCreatePolicy policy = do
  statement (unPolicyId $ policyId policy, hostname policy, toJSON policy) insertPolicy
  case policyName policy of
    Nothing -> return ()
    Just name -> do
      statement (unPolicyId $ policyId policy, name) insertPolicyName
  return $ Right policy


pgUpdatePolicy :: Policy -> Transaction (Either Error Policy)
pgUpdatePolicy policy = do
  statement (unPolicyId $ policyId policy, toJSON policy) updatePolicy
  return $ Right policy


pgDeletePolicy :: PolicyIdentifier -> Transaction (Either Error Policy)
pgDeletePolicy (PolicyId (PolicyUUID pid)) = do
  result <- pgGetPolicy $ PolicyId $ PolicyUUID pid
  case result of
    Left e -> return $ Left e
    Right policy -> do
      statement pid deletePolicy
      return $ Right policy
pgDeletePolicy (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyName name
    Just pid -> pgDeletePolicy $ PolicyId $ PolicyUUID pid
pgDeletePolicy (PolicyIdAndName (PolicyUUID pid) _) =
  pgDeletePolicy $ PolicyId $ PolicyUUID pid


pgCreateMembership ::
  UserIdentifier -> GroupIdentifier -> Transaction (Either Error Membership)
pgCreateMembership userIdentifier groupIdentifier = do
  maybeUid <- resolveUserIdentifier userIdentifier
  maybeGid <- resolveGroupIdentifier groupIdentifier
  case (maybeUid, maybeGid) of
    (Just (UserUUID uid), Just (GroupUUID gid)) -> do
      statement (uid, gid) insertMembership
      return $ Right $ Membership (UserUUID uid) (GroupUUID gid)
    (Nothing, _) ->
      return $ Left $ NotFound $ UserNotFound userIdentifier
    (_, Nothing) ->
      return $ Left $ NotFound $ GroupNotFound groupIdentifier


pgDeleteMembership ::
  UserIdentifier -> GroupIdentifier -> Transaction (Either Error Membership)
pgDeleteMembership userIdentifier groupIdentifier = do
  maybeUid <- resolveUserIdentifier userIdentifier
  maybeGid <- resolveGroupIdentifier groupIdentifier
  case (maybeUid, maybeGid) of
    (Just (UserUUID uid), Just (GroupUUID gid)) -> do
      statement (uid, gid) deleteMembership
      return $ Right $ Membership (UserUUID uid) (GroupUUID gid)
    (Nothing, _) ->
      return $ Left $ NotFound $ UserNotFound userIdentifier
    (_, Nothing) ->
      return $ Left $ NotFound $ GroupNotFound groupIdentifier


pgCreateUserPolicyAttachment ::
  UserIdentifier -> PolicyIdentifier -> Transaction (Either Error UserPolicyAttachment)
pgCreateUserPolicyAttachment userIdentifier (PolicyId (PolicyUUID pid)) = do
  maybeUid <- resolveUserIdentifier userIdentifier
  case maybeUid of
    Just (UserUUID uid) -> do
      statement (uid, pid) insertUserPolicyAttachment
      return $ Right $ UserPolicyAttachment (UserUUID uid) (PolicyUUID pid)
    Nothing -> return $ Left $ NotFound $ UserNotFound userIdentifier
pgCreateUserPolicyAttachment userIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyName name
    Just pid -> pgCreateUserPolicyAttachment userIdentifier $ PolicyId $ PolicyUUID pid
pgCreateUserPolicyAttachment userIdentifier (PolicyIdAndName (PolicyUUID pid) _) =
  pgCreateUserPolicyAttachment userIdentifier $ PolicyId $ PolicyUUID pid


pgDeleteUserPolicyAttachment ::
  UserIdentifier -> PolicyIdentifier -> Transaction (Either Error UserPolicyAttachment)
pgDeleteUserPolicyAttachment userIdentifier (PolicyId (PolicyUUID pid)) = do
  maybeUid <- resolveUserIdentifier userIdentifier
  case maybeUid of
    Just (UserUUID uid) -> do
      statement (uid, pid) deleteUserPolicyAttachment
      return $ Right $ UserPolicyAttachment (UserUUID uid) (PolicyUUID pid)
    Nothing -> return $ Left $ NotFound $ UserNotFound userIdentifier
pgDeleteUserPolicyAttachment userIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyName name
    Just pid -> pgDeleteUserPolicyAttachment userIdentifier $ PolicyId $ PolicyUUID pid
pgDeleteUserPolicyAttachment userIdentifier (PolicyIdAndName (PolicyUUID pid) _) =
  pgDeleteUserPolicyAttachment userIdentifier $ PolicyId $ PolicyUUID pid


pgCreateGroupPolicyAttachment ::
  GroupIdentifier -> PolicyIdentifier -> Transaction (Either Error GroupPolicyAttachment)
pgCreateGroupPolicyAttachment groupIdentifier (PolicyId (PolicyUUID pid)) = do
  maybeGid <- resolveGroupIdentifier groupIdentifier
  case maybeGid of
    Just (GroupUUID gid) -> do
      statement (gid, pid) insertGroupPolicyAttachment
      return $ Right $ GroupPolicyAttachment (GroupUUID gid) (PolicyUUID pid)
    Nothing -> return $ Left $ NotFound $ GroupNotFound groupIdentifier
pgCreateGroupPolicyAttachment groupIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyName name
    Just pid -> pgCreateGroupPolicyAttachment groupIdentifier $ PolicyId $ PolicyUUID pid
pgCreateGroupPolicyAttachment groupIdentifier (PolicyIdAndName (PolicyUUID pid) _) =
  pgCreateGroupPolicyAttachment groupIdentifier $ PolicyId $ PolicyUUID pid


pgDeleteGroupPolicyAttachment ::
  GroupIdentifier -> PolicyIdentifier -> Transaction (Either Error GroupPolicyAttachment)
pgDeleteGroupPolicyAttachment groupIdentifier (PolicyId (PolicyUUID pid)) = do
  maybeGid <- resolveGroupIdentifier groupIdentifier
  case maybeGid of
    Just (GroupUUID gid) -> do
      statement (gid, pid) deleteGroupPolicyAttachment
      return $ Right $ GroupPolicyAttachment (GroupUUID gid) (PolicyUUID pid)
    Nothing -> return $ Left $ NotFound $ GroupNotFound groupIdentifier
pgDeleteGroupPolicyAttachment groupIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyNotFound $ PolicyName name
    Just pid -> pgDeleteGroupPolicyAttachment groupIdentifier $ PolicyId $ PolicyUUID pid
pgDeleteGroupPolicyAttachment groupIdentifier (PolicyIdAndName (PolicyUUID pid) _) =
  pgDeleteGroupPolicyAttachment groupIdentifier $ PolicyId $ PolicyUUID pid


pgCreateSession :: CreateSession -> Transaction (Either Error CreateSession)
pgCreateSession session = do
  let CreateSession sid uid token expires = session
  statement (unSessionId sid, unUserId uid, token, expires) insertSession
  return $ Right session


pgDeleteSession :: UserIdentifier -> SessionId -> Transaction (Either Error Session)
pgDeleteSession uid sid = do
  result <- pgGetSessionById uid sid
  case result of
    Left e -> return $ Left e
    Right session -> do
      statement (unSessionId sid) deleteSession
      return $ Right session


pgRefreshSession :: UserIdentifier -> SessionId -> Transaction (Either Error Session)
pgRefreshSession uid sid = do
  result <- pgGetSessionById uid sid
  case result of
    Left e -> return $ Left e
    Right session -> do
      let session' = refreshSession session
      statement (unSessionId sid, sessionExpiration session') updateSessionExpiration
      return $ Right session'


pgGetSessionById :: UserIdentifier -> SessionId -> Transaction (Either Error Session)
pgGetSessionById uid sid = do
  maybeUid <- resolveUserIdentifier uid
  case maybeUid of
    Just (UserUUID uuid) -> do
      result <- statement (uuid, unSessionId sid) selectSessionById
      case result of
        Nothing ->
          return $ Left $ NotFound $ SessionNotFound $ Just sid
        Just (_, expires) ->
          return $ Right $ Session sid (UserUUID uuid) expires
    Nothing -> return $ Left $ NotFound $ UserNotFound uid


pgGetSessionByToken :: UserIdentifier -> Text -> Transaction (Either Error Session)
pgGetSessionByToken uid token = do
  maybeUid <- resolveUserIdentifier uid
  case maybeUid of
    Just (UserUUID uuid) -> do
      result <- statement (uuid, token) selectSessionByToken
      case result of
        Nothing -> return $ Left $ NotFound $ SessionNotFound Nothing
        Just (sid, expires) ->
          return $ Right $ Session (SessionUUID sid) (UserUUID uuid) expires
    Nothing -> return $ Left $ NotFound $ UserNotFound uid


pgListUserSessions :: UserIdentifier -> Range -> Transaction (Either Error [Session])
pgListUserSessions userIdentifier (Range offset maybeLimit) = do
  let limit = fromMaybe 100 maybeLimit
  maybeUid <- resolveUserIdentifier userIdentifier
  case maybeUid of
    Just (UserUUID uid) -> do
      let params = (uid, fromIntegral offset, fromIntegral limit)
      result <- statement params selectUserSessions
      return $ Right $ map (session uid) $ toList result
    Nothing -> return $ Left $ NotFound $ UserNotFound userIdentifier
  where
    session uid (sid, _, expires) = Session (SessionUUID sid) (UserUUID uid) expires


resolveUserIdentifier :: UserIdentifier -> Transaction (Maybe UserId)
resolveUserIdentifier userIdentifier =
  case unUserIdentifier userIdentifier of
    Left email -> do
      result <- statement email selectUserIdByEmail
      case result of
        Nothing -> return Nothing
        Just uuid' -> return $ Just $ UserUUID uuid'
    Right (UserUUID uuid) -> return $ Just $ UserUUID uuid


resolveGroupIdentifier :: GroupIdentifier -> Transaction (Maybe GroupId)
resolveGroupIdentifier groupIdentifier =
  case unGroupIdentifier groupIdentifier of
    Left name -> do
      result <- statement name selectGroupIdByName
      case result of
        Nothing -> return Nothing
        Just uuid' -> return $ Just $ GroupUUID uuid'
    Right (GroupUUID uuid) -> return $ Just $ GroupUUID uuid


resolvePolicyIdentifier :: PolicyIdentifier -> Transaction (Maybe PolicyId)
resolvePolicyIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return Nothing
    Just pid -> return $ Just $ PolicyUUID pid
resolvePolicyIdentifier (PolicyId (PolicyUUID pid)) = do
  return $ Just $ PolicyUUID pid
resolvePolicyIdentifier (PolicyIdAndName (PolicyUUID pid) _) =
  return $ Just $ PolicyUUID pid


resolveUserGroups :: [GroupIdentifier] -> Transaction (Either Error [GroupId])
resolveUserGroups [] = return $ Right []
resolveUserGroups (gident:rest) = do
  result <- resolveGroupIdentifier gident
  case result of
    Nothing ->
      return $ Left $ NotFound $ GroupNotFound gident
    Just (GroupUUID guuid) -> do
      result' <- resolveUserGroups rest
      case result' of
        Left e -> return $ Left e
        Right gids -> return $ Right $ GroupUUID guuid : gids


resolvePolicies :: [PolicyIdentifier] -> Transaction (Either Error [PolicyId])
resolvePolicies [] = return $ Right []
resolvePolicies (pident:rest) = do
  result <- resolvePolicyIdentifier pident
  case result of
    Nothing ->
      return $ Left $ NotFound $ PolicyNotFound pident
    Just (PolicyUUID pid) -> do
      result' <- resolvePolicies rest
      case result' of
        Left e -> return $ Left e
        Right pids -> return $ Right $ PolicyUUID pid : pids
