{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.DB.Postgres.Transactions
  ( module IAM.Server.DB.Postgres.Transactions
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.Aeson (Result(..), fromJSON, toJSON)
import Data.Maybe
import Data.Text (Text, pack, unpack)
import Data.UUID (UUID)
import Data.Vector (toList)
import Hasql.Transaction (Transaction, statement)

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
import IAM.Server.DB.Postgres.Queries
import IAM.Range
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserPolicy
import IAM.UserPublicKey
import IAM.UserIdentifier


pgEscapeLike :: Text -> Text
pgEscapeLike = pack . concatMap escapeChar . unpack
  where
    escapeChar '%' = ['\\', '%']
    escapeChar '_' = ['\\', '_']
    escapeChar c = [c]


pgCreateLoginResponse ::
  LoginResponse SessionId -> Transaction (Either Error (LoginResponse SessionId))
pgCreateLoginResponse lr = do
  statement lr insertLoginRequest
  return $ Right lr


pgGetLoginResponse ::
  UserIdentifier -> LoginRequestId -> Transaction (Either Error (LoginResponse SessionId))
pgGetLoginResponse uident lid = do
  maybeUid <- resolveUserIdentifier uident
  case maybeUid of
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uident
    Just uid -> do
      result <- statement (uid, lid) selectLoginRequest
      case result of
        Nothing -> return $ Left $ NotFound $ LoginIdentifier lid
        Just lr -> return $ Right lr


pgListLoginResponses ::
  UserIdentifier -> Range ->
    Transaction (Either Error (ListResponse (LoginResponse SessionId)))
pgListLoginResponses uident (Range offset' maybeLimit) = do
  maybeUid <- resolveUserIdentifier uident
  case maybeUid of
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uident
    Just uid -> do
      let limit' = fromMaybe 100 maybeLimit
      let offset'' = fromIntegral offset'
      let limit'' = fromIntegral limit'
      total' <- statement uid selectLoginRequestsByUserIdCount
      result <- statement (uid, (offset'', limit'')) selectLoginRequestsByUserId
      return $ Right $ ListResponse result limit' offset' $ fromIntegral total'


pgDeleteLoginResponse ::
  UserIdentifier -> LoginRequestId ->
    Transaction (Either Error (LoginResponse SessionId))
pgDeleteLoginResponse uident lid = do
  maybeUid <- resolveUserIdentifier uident
  case maybeUid of
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uident
    Just uid -> do
      result <- statement (uid, lid) selectLoginRequest
      case result of
        Nothing -> return $ Left $ NotFound $ LoginIdentifier lid
        Just lr -> do
          statement (uid, lid) deleteLoginRequest
          return $ Right lr


pgUpdateLoginResponse ::
  UserIdentifier -> LoginRequestId ->
    (LoginResponse SessionId -> LoginResponse SessionId) ->
      Transaction (Either Error (LoginResponse SessionId))
pgUpdateLoginResponse uident lid f = do
  maybeUid <- resolveUserIdentifier uident
  case maybeUid of
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uident
    Just uid -> do
      result <- statement (uid, lid) selectLoginRequest
      case result of
        Nothing -> return $ Left $ NotFound $ LoginIdentifier lid
        Just lr -> do
          let lr' = f lr
          statement lr' upsertLoginRequest
          return $ Right lr'


pgGetUser :: UserIdentifier -> Transaction (Either Error User)
pgGetUser (UserIdentifier (Just uid) _ _) = pgGetUserById uid
pgGetUser (UserIdentifier Nothing (Just name) _) = pgGetUserByName name
pgGetUser (UserIdentifier Nothing Nothing (Just email)) = pgGetUserByEmail email
pgGetUser uid = return $ Left $ NotFound $ UserIdentifier' uid


pgGetUserByName :: Text -> Transaction (Either Error User)
pgGetUserByName name = do
  result0 <- statement name selectUserIdByName
  case result0 of
    Nothing ->
      let uid = UserIdentifier Nothing (Just name) Nothing
       in return $ Left $ NotFound $ UserIdentifier' uid
    Just uuid' -> do
      pgGetUserById $ UserUUID uuid'


pgGetUserByEmail :: Text -> Transaction (Either Error User)
pgGetUserByEmail email = do
  result0 <- statement email selectUserIdByEmail
  case result0 of
    Nothing ->
      let uid = UserIdentifier Nothing Nothing (Just email)
       in return $ Left $ NotFound $ UserIdentifier' uid
    Just uuid' -> do
      pgGetUserById $ UserUUID uuid'


pgGetUserById :: UserId -> Transaction (Either Error User)
pgGetUserById (UserUUID uuid) = do
  result <- statement uuid selectUserId
  case result of
    Nothing -> return $ Left $ NotFound $ UserIdentifier' $
      UserIdentifier (Just $ UserUUID uuid) Nothing Nothing
    Just _ -> do
      mName <- statement uuid selectUserName
      mEmail <- statement uuid selectUserEmail
      r0 <- statement uuid selectUserGroups
      r1 <- statement uuid selectUserPolicyIdentifiers
      r2 <- statement uuid selectUserPublicKeys
      let groups = map group $ toList r0
      let publicKeys = map pk $ toList r2
      let policies = map pid $ toList r1
      return $ Right $ User (UserUUID uuid) mName mEmail groups policies publicKeys
  where
    group (guuid, Nothing) = GroupId $ GroupUUID guuid
    group (guuid, Just name) = GroupIdAndName (GroupUUID guuid) name
    pid (pid', Nothing) = PolicyId $ PolicyUUID pid'
    pid (pid', Just name) = PolicyIdAndName (PolicyUUID pid') name
    pk (pkBytes, pkDescription) = UserPublicKey (PublicKey pkBytes) pkDescription


pgGetUserId :: UserIdentifier -> Transaction (Either Error UserId)
pgGetUserId (UserIdentifier (Just uid) _ _) = return $ Right uid
pgGetUserId (UserIdentifier Nothing (Just name) _) = do
  result <- statement name selectUserIdByName
  case result of
    Just uuid' -> return $ Right $ UserUUID uuid'
    Nothing ->
      let uid = UserIdentifier Nothing (Just name) Nothing
       in return $ Left $ NotFound $ UserIdentifier' uid
pgGetUserId (UserIdentifier Nothing Nothing (Just email)) = do
  result <- statement email selectUserIdByEmail
  case result of
    Just uuid' -> return $ Right $ UserUUID uuid'
    Nothing ->
      let uid = UserIdentifier Nothing Nothing (Just email)
       in return $ Left $ NotFound $ UserIdentifier' uid
pgGetUserId uid = return $ Left $ NotFound $ UserIdentifier' uid


pgListUsers ::
  Range -> SortUsersBy -> SortOrder ->
  Transaction (Either Error (ListResponse UserIdentifier))
pgListUsers (Range offset' Nothing) sort order =
  pgListUsers (Range offset' $ Just 100) sort order
pgListUsers (Range offset' (Just limit')) sort order = do
  let limit'' = fromIntegral limit'
  let offset'' = fromIntegral offset'
  let query = case (sort, order) of
        (SortUsersById, Ascending) ->
          selectUserIdentifiersOrderByIdAsc
        (SortUsersById, Descending) ->
          selectUserIdentifiersOrderByIdDesc
        (SortUsersByName, Ascending) ->
          selectUserIdentifiersOrderByNameAsc
        (SortUsersByName, Descending) ->
          selectUserIdentifiersOrderByNameDesc
        (SortUsersByEmail, Ascending) ->
          selectUserIdentifiersOrderByEmailAsc
        (SortUsersByEmail, Descending) ->
          selectUserIdentifiersOrderByEmailDesc
  total' <- statement () selectUserCount
  result <- statement (offset'', limit'') query
  let items' = map userIdentifier $ toList result
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
  where
    userIdentifier (uuuid, mName, mEmail) =
      UserIdentifier (Just $ UserUUID uuuid) mName mEmail
          

pgListUsersBySearchTerm ::
  Text -> Range -> SortUsersBy -> SortOrder ->
  Transaction (Either Error (ListResponse UserIdentifier))
pgListUsersBySearchTerm search (Range offset' Nothing) sort order =
  pgListUsersBySearchTerm search (Range offset' $ Just 100) sort order
pgListUsersBySearchTerm search (Range offset' (Just limit')) sort order = do
  let likeExpr = "%" <> pgEscapeLike search <> "%"
  let query = case (sort, order) of
        (SortUsersById, Ascending) -> selectUserIdentifiersLikeOrderByIdAsc
        (SortUsersByName, Ascending) -> selectUserIdentifiersLikeOrderByNameAsc
        (SortUsersByEmail, Ascending) -> selectUserIdentifiersLikeOrderByEmailAsc
        (SortUsersById, Descending) -> selectUserIdentifiersLikeOrderByIdDesc
        (SortUsersByName, Descending) -> selectUserIdentifiersLikeOrderByNameDesc
        (SortUsersByEmail, Descending) -> selectUserIdentifiersLikeOrderByEmailDesc
  total' <- statement likeExpr selectUserCountLike
  result <- statement (likeExpr, fromIntegral offset', fromIntegral limit') query
  let items' = map userIdentifier $ toList result
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
  where
    userIdentifier (uuuid, mName, mEmail) =
      UserIdentifier (Just $ UserUUID uuuid) mName mEmail


pgCreateUser :: User -> Transaction (Either Error User)
pgCreateUser (User uid mName mEmail groups policies publicKeys) = do
  result0 <- statement (unUserId uid) selectUserId
  result1 <- emailQuery mEmail

  case (result0, result1) of
    (Just _, _) -> return $ Left AlreadyExists
    (_, Just _) -> return $ Left AlreadyExists
    (Nothing, Nothing) -> do
      statement (unUserId uid) insertUserId

      case mName of
        Nothing -> return ()
        Just name -> do
          statement (uid, name) upsertUserName

      case mEmail of
        Nothing -> return ()
        Just email -> do
          statement (uid, email) upsertUserEmail

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

              return $ Right $
                User uid mName mEmail groups policies publicKeys

  where

  emailQuery :: Maybe Text -> Transaction (Maybe UUID)
  emailQuery Nothing = return Nothing
  emailQuery (Just email) = do
    result <- statement email selectUserIdByEmail
    case result of
      Nothing -> return Nothing
      Just uuuid -> return $ Just uuuid

  insertUserGroup' :: GroupId -> Transaction ()
  insertUserGroup' (GroupUUID guuid) = statement (unUserId uid, guuid) insertUserGroup

  insertUserPolicy' :: UUID -> Transaction ()
  insertUserPolicy' pid = statement (unUserId uid, pid) insertUserPolicy

  insertUserPublicKey' :: UserPublicKey -> Transaction ()
  insertUserPublicKey' (UserPublicKey (PublicKey pk) description) =
    statement (unUserId uid, pk, description) insertUserPublicKey


pgUpdateUser :: UserIdentifier -> UserUpdate -> Transaction (Either Error User)
pgUpdateUser uident uupdate = do
  maybeUid <- resolveUserIdentifier uident
  case maybeUid of
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uident
    Just uid -> do
      let mName = userUpdateName uupdate
      let mEmail = userUpdateEmail uupdate
      case mName of
        Nothing -> return ()
        Just Nothing -> do
          statement uid deleteUserName
        Just (Just name) -> do
          statement (uid, name) upsertUserName
      case mEmail of
        Nothing -> return ()
        Just Nothing -> do
          statement uid deleteUserEmail
        Just (Just email) -> do
          statement (uid, email) upsertUserEmail
      pgGetUserById uid


pgUpsertUserPublicKey ::
  UserId -> UserPublicKey -> Transaction (Either Error UserPublicKey)
pgUpsertUserPublicKey uid pk = do
  statement (uid, pk) upsertUserPublicKey
  return $ Right pk


pgListUserPublicKeys ::
  UserId -> Range -> Transaction (Either Error (ListResponse UserPublicKey))
pgListUserPublicKeys uid (Range offset' maybeLimit) = do
  let limit' = fromMaybe 100 maybeLimit
  let offset'' = fromIntegral offset'
  let limit'' = fromIntegral limit'
  total' <- statement uid selectUserPublicKeysCount
  items' <- statement (uid, (offset'', limit'')) selectUserPublicKeysRange
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'


pgGetUserPublicKey ::
  UserId -> PublicKey -> Transaction (Either Error UserPublicKey)
pgGetUserPublicKey uid pk = do
  result <- statement (uid, pk) selectUserPublicKey
  case result of
    Nothing -> return $ Left $ NotFound $ UserPublicKeyIdentifier uid pk
    Just upk -> return $ Right upk


pgDeleteUserPublicKey ::
  UserId -> PublicKey -> Transaction (Either Error UserPublicKey)
pgDeleteUserPublicKey uid pk = do
  result <- pgGetUserPublicKey uid pk
  case result of
    Left e -> return $ Left e
    Right upk -> do
      statement (uid, pk) deleteUserPublicKey
      return $ Right upk


pgDeleteUser :: UserIdentifier -> Transaction (Either Error User)
pgDeleteUser (UserIdentifier (Just uid) _ _) = pgDeleteUserById uid
pgDeleteUser (UserIdentifier Nothing (Just name) _) = pgDeleteUserByName name
pgDeleteUser (UserIdentifier Nothing Nothing (Just email)) = pgDeleteUserByEmail email
pgDeleteUser uid = return $ Left $ NotFound $ UserIdentifier' uid


pgDeleteUserByName :: Text -> Transaction (Either Error User)
pgDeleteUserByName name = do
  result0 <- statement name selectUserIdByName
  case result0 of
    Just uuid' -> pgDeleteUserById $ UserUUID uuid'
    Nothing ->
      let uid = UserIdentifier Nothing (Just name) Nothing
       in return $ Left $ NotFound $ UserIdentifier' uid


pgDeleteUserByEmail :: Text -> Transaction (Either Error User)
pgDeleteUserByEmail email = do
  result0 <- statement email selectUserIdByEmail
  case result0 of
    Just uuid' -> pgDeleteUserById $ UserUUID uuid'
    Nothing ->
      let uid = UserIdentifier Nothing Nothing (Just email)
       in return $ Left $ NotFound $ UserIdentifier' uid


pgDeleteUserById :: UserId -> Transaction (Either Error User)
pgDeleteUserById (UserUUID uuid) = do
  result <- pgGetUserById $ UserUUID uuid
  case result of
    Left e -> return $ Left e
    Right user -> do
      statement uuid deleteUserPublicKeys
      statement uuid deleteUserPolicies
      statement uuid deleteUserGroups
      statement (UserUUID uuid) deleteUserEmail
      statement (UserUUID uuid) deleteUserId
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
    Nothing -> return $ Left $ NotFound $ GroupIdentifier $ GroupName name
    Just uuid' -> pgGetGroupById $ GroupUUID uuid'


pgGetGroupById :: GroupId -> Transaction (Either Error Group)
pgGetGroupById (GroupUUID uuid) = do
  result <- statement uuid selectGroupId
  case result of
    Nothing -> return $ Left $ NotFound $ GroupIdentifier $ GroupId $ GroupUUID uuid
    Just _ -> do
      maybeName <- statement uuid selectGroupName
      r0 <- statement uuid selectGroupUsers
      r1 <- statement uuid selectGroupPolicyIdentifiers
      let users = map user $ toList r0
      let policies = map pid $ toList r1
      return $ Right $ Group (GroupUUID uuid) maybeName users policies
  where
    user (uuuid, mName, mEmail) = UserIdentifier (Just $ UserUUID uuuid) mName mEmail
    pid (pid', Nothing) = PolicyId $ PolicyUUID pid'
    pid (pid', Just name) = PolicyIdAndName (PolicyUUID pid') name


pgListGroups :: Range -> SortGroupsBy -> SortOrder ->
  Transaction (Either Error (ListResponse GroupIdentifier))
pgListGroups (Range offset' maybeLimit) sort order = do
  let limit' = fromMaybe 100 maybeLimit
  let query = case (sort, order) of
        (SortGroupsById, Ascending) -> selectGroupIdentifiersOrderByIdAsc
        (SortGroupsById, Descending) -> selectGroupIdentifiersOrderByIdDesc
        (SortGroupsByName, Ascending) -> selectGroupIdentifiersOrderByNameAsc
        (SortGroupsByName, Descending) -> selectGroupIdentifiersOrderByNameDesc
  result <- statement (fromIntegral offset', fromIntegral limit') query
  let items' = map groupIdentifier $ toList result
  total' <- statement () selectGroupCount
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
  where
    groupIdentifier (guuid, Nothing) = GroupId $ GroupUUID guuid
    groupIdentifier (guuid, Just name) = GroupIdAndName (GroupUUID guuid) name


pgListGroupsBySearchTerm :: Text -> Range -> SortGroupsBy -> SortOrder ->
  Transaction (Either Error (ListResponse GroupIdentifier))
pgListGroupsBySearchTerm search (Range offset' maybeLimit) sort order = do
  let limit' = fromMaybe 100 maybeLimit
  let likeExpr = "%" <> pgEscapeLike search <> "%"
  let query = case (sort, order) of
        (SortGroupsById, Ascending) -> selectGroupIdentifiersLikeOrderByIdAsc
        (SortGroupsById, Descending) -> selectGroupIdentifiersLikeOrderByIdDesc
        (SortGroupsByName, Ascending) -> selectGroupIdentifiersLikeOrderByNameAsc
        (SortGroupsByName, Descending) -> selectGroupIdentifiersLikeOrderByNameDesc
  result <- statement (likeExpr, fromIntegral offset', fromIntegral limit') query
  let items' = map groupIdentifier $ toList result
  total' <- statement likeExpr selectGroupCountLike
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
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
        return $ Left $ NotFound $ UserIdentifier' uident
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
    Nothing -> return $ Left $ NotFound $ GroupIdentifier $ GroupName name
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
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyId $ PolicyUUID pid
    Just policy ->
      case fromJSON policy of
        Error e -> return $ Left $ InternalError $ pack $ show e
        Success p -> return $ Right p
pgGetPolicy (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyName name
    Just pid -> pgGetPolicy $ PolicyId $ PolicyUUID pid
pgGetPolicy (PolicyIdAndName (PolicyUUID pid) _) =
  pgGetPolicy $ PolicyId $ PolicyUUID pid


pgListPolicies ::
  Range -> SortPoliciesBy -> SortOrder ->
    Transaction (Either Error (ListResponse PolicyIdentifier))
pgListPolicies (Range offset' maybeLimit) sort order = do
  let limit' = fromMaybe 100 maybeLimit
  let query = case (sort, order) of
        (SortPoliciesById, Ascending) -> selectPolicyIdentifiersOrderByIdAsc
        (SortPoliciesById, Descending) -> selectPolicyIdentifiersOrderByIdDesc
        (SortPoliciesByName, Ascending) -> selectPolicyIdentifiersOrderByNameAsc
        (SortPoliciesByName, Descending) -> selectPolicyIdentifiersOrderByNameDesc
  result <- statement (fromIntegral offset', fromIntegral limit') query
  total' <- statement () selectPolicyCount
  let items' = map policyIdentifier $ toList result
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
  where
    policyIdentifier (pid, Nothing) = PolicyId $ PolicyUUID pid
    policyIdentifier (pid, Just name) = PolicyIdAndName (PolicyUUID pid) name


pgListPoliciesBySearchTerm :: Text -> Range -> SortPoliciesBy -> SortOrder ->
  Transaction (Either Error (ListResponse PolicyIdentifier))
pgListPoliciesBySearchTerm search (Range offset' maybeLimit) sort order = do
  let limit' = fromMaybe 100 maybeLimit
  let likeExpr = "%" <> pgEscapeLike search <> "%"
  let query = case (sort, order) of
        (SortPoliciesById, Ascending) -> selectPolicyIdentifiersLikeOrderByIdAsc
        (SortPoliciesById, Descending) -> selectPolicyIdentifiersLikeOrderByIdDesc
        (SortPoliciesByName, Ascending) -> selectPolicyIdentifiersLikeOrderByNameAsc
        (SortPoliciesByName, Descending) -> selectPolicyIdentifiersLikeOrderByNameDesc
  result <- statement (likeExpr, fromIntegral offset', fromIntegral limit') query
  total' <- statement likeExpr selectPolicyCountLike
  let items' = map policyIdentifier $ toList result
  return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
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
    Nothing -> return $ Left $ NotFound $ GroupIdentifier $ GroupName name
    Just uuid' -> pgListPoliciesForGroupById host $ GroupUUID uuid'


pgListPoliciesForGroupById :: Text -> GroupId -> Transaction (Either Error [Policy])
pgListPoliciesForGroupById host (GroupUUID uuid) = do
  r0 <- statement (uuid, host) selectGroupPoliciesForHost
  case mapM fromJSON $ toList r0 of
    Error e -> return $ Left $ InternalError $ pack $ show e
    Success policies -> return $ Right policies


pgCreatePolicy :: Policy -> Transaction (Either Error Policy)
pgCreatePolicy policy = do
  case policyName policy of
    Nothing -> pgCreatePolicy'
    Just name -> do
      result <- statement name selectPolicyIdByName
      case result of
        Nothing -> pgCreatePolicy'
        Just _ -> return $ Left AlreadyExists
  where
    pgCreatePolicy' :: Transaction (Either Error Policy)
    pgCreatePolicy' = do
      let pid = unPolicyId $ policyId policy
      statement (pid, hostname policy, toJSON policy) insertPolicy
      case policyName policy of
        Nothing -> return ()
        Just name -> statement (pid, name) insertPolicyName
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
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyName name
    Just pid -> pgDeletePolicy $ PolicyId $ PolicyUUID pid
pgDeletePolicy (PolicyIdAndName (PolicyUUID pid) _) =
  pgDeletePolicy $ PolicyId $ PolicyUUID pid


pgGetMembership ::
  UserIdentifier -> GroupIdentifier -> Transaction (Either Error Membership)
pgGetMembership userIdentifier groupIdentifier = do
  maybeUid <- resolveUserIdentifier userIdentifier
  maybeGid <- resolveGroupIdentifier groupIdentifier
  case (maybeUid, maybeGid) of
    (Just (UserUUID uid), Just (GroupUUID gid)) -> do
      result <- statement (uid, gid) selectUserGroup
      case result of
        Nothing -> return $ Left $ NotFound $
          UserGroupIdentifier userIdentifier groupIdentifier
        Just _ -> return $ Right $ Membership (UserUUID uid) (GroupUUID gid)
    (Nothing, _) ->
      return $ Left $ NotFound $ UserIdentifier' userIdentifier
    (_, Nothing) ->
      return $ Left $ NotFound $ GroupIdentifier groupIdentifier


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
      return $ Left $ NotFound $ UserIdentifier' userIdentifier
    (_, Nothing) ->
      return $ Left $ NotFound $ GroupIdentifier groupIdentifier


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
      return $ Left $ NotFound $ UserIdentifier' userIdentifier
    (_, Nothing) ->
      return $ Left $ NotFound $ GroupIdentifier groupIdentifier


pgCreateUserPolicyAttachment ::
  UserIdentifier -> PolicyIdentifier -> Transaction (Either Error UserPolicyAttachment)
pgCreateUserPolicyAttachment userIdentifier (PolicyId (PolicyUUID pid)) = do
  maybeUid <- resolveUserIdentifier userIdentifier
  case maybeUid of
    Just (UserUUID uid) -> do
      statement (uid, pid) insertUserPolicyAttachment
      return $ Right $ UserPolicyAttachment (UserUUID uid) (PolicyUUID pid)
    Nothing -> return $ Left $ NotFound $ UserIdentifier' userIdentifier
pgCreateUserPolicyAttachment userIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyName name
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
    Nothing -> return $ Left $ NotFound $ UserIdentifier' userIdentifier
pgDeleteUserPolicyAttachment userIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyName name
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
    Nothing -> return $ Left $ NotFound $ GroupIdentifier groupIdentifier
pgCreateGroupPolicyAttachment groupIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyName name
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
    Nothing -> return $ Left $ NotFound $ GroupIdentifier groupIdentifier
pgDeleteGroupPolicyAttachment groupIdentifier (PolicyName name) = do
  result <- statement name selectPolicyIdByName
  case result of
    Nothing -> return $ Left $ NotFound $ PolicyIdentifier $ PolicyName name
    Just pid -> pgDeleteGroupPolicyAttachment groupIdentifier $ PolicyId $ PolicyUUID pid
pgDeleteGroupPolicyAttachment groupIdentifier (PolicyIdAndName (PolicyUUID pid) _) =
  pgDeleteGroupPolicyAttachment groupIdentifier $ PolicyId $ PolicyUUID pid


pgCreateSession :: CreateSession -> Transaction (Either Error CreateSession)
pgCreateSession session = do
  let CreateSession sid addr uid token expires = session
  statement (unSessionId sid, unUserId uid, unIpAddr addr, token, expires) insertSession
  return $ Right session


pgDeleteSession :: SessionId -> Transaction (Either Error Session)
pgDeleteSession sid = do
  result <- pgGetSessionById sid
  case result of
    Left e -> return $ Left e
    Right session -> do
      statement (unSessionId sid) deleteSession
      return $ Right session


pgDeleteUserSession :: UserIdentifier -> SessionId -> Transaction (Either Error Session)
pgDeleteUserSession uid sid = do
  result <- pgGetUserSessionById uid sid
  case result of
    Left e -> return $ Left e
    Right session -> do
      statement (unSessionId sid) deleteSession
      return $ Right session


pgRefreshSession :: UserIdentifier -> SessionId -> Transaction (Either Error Session)
pgRefreshSession uid sid = do
  result <- pgGetUserSessionById uid sid
  case result of
    Left e -> return $ Left e
    Right session -> do
      let session' = refreshSession session
      statement (unSessionId sid, sessionExpiration session') updateSessionExpiration
      return $ Right session'


pgGetSessionById :: SessionId -> Transaction (Either Error Session)
pgGetSessionById sid = do
  result <- statement (unSessionId sid) selectSessionById
  case result of
    Nothing -> return $ Left $ NotFound $ SessionIdentifier $ Just sid
    Just (uid, addr, expires) ->
      return $ Right $ Session sid (IpAddr addr) (UserUUID uid) expires


pgGetUserSessionById :: UserIdentifier -> SessionId -> Transaction (Either Error Session)
pgGetUserSessionById uid sid = do
  maybeUid <- resolveUserIdentifier uid
  case maybeUid of
    Just uid' -> loadSession uid' sid
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uid


pgGetSessionByToken :: UserIdentifier -> Text -> Transaction (Either Error Session)
pgGetSessionByToken uid token = do
  maybeUid <- resolveUserIdentifier uid
  case maybeUid of
    Just (UserUUID uuid) -> do
      result <- statement (uuid, token) selectSessionByToken
      case result of
        Nothing -> return $ Left $ NotFound $ SessionIdentifier Nothing
        Just (sid, addr, expiry) ->
          return $ Right $ Session (SessionUUID sid) (IpAddr addr) (UserUUID uuid) expiry
    Nothing -> return $ Left $ NotFound $ UserIdentifier' uid


pgListSessions :: Range -> Transaction (Either Error (ListResponse Session))
pgListSessions (Range offset' maybeLimit) = do
  let limit' = fromMaybe 100 maybeLimit
  let offset'' = fromIntegral offset'
  let limit'' = fromIntegral limit'
  total' <- statement () selectSessionCount
  result <- statement (offset'', limit'') selectSessions
  return $ Right $ ListResponse result limit' offset' $ fromIntegral total'


pgListUserSessions :: UserIdentifier -> Range ->
  Transaction (Either Error (ListResponse Session))
pgListUserSessions userIdentifier (Range offset' maybeLimit) = do
  let limit' = fromMaybe 100 maybeLimit
  maybeUid <- resolveUserIdentifier userIdentifier
  case maybeUid of
    Just (UserUUID uid) -> do
      let params = (uid, fromIntegral offset', fromIntegral limit')
      result <- statement params selectUserSessions
      total' <- statement uid selectUserSessionCount
      let items' = map (session uid) $ toList result
      return $ Right $ ListResponse items' limit' offset' $ fromIntegral total'
    Nothing -> return $ Left $ NotFound $ UserIdentifier' userIdentifier
  where
    session uid (sid, addr, expires) =
      Session (SessionUUID sid) (IpAddr addr) (UserUUID uid) expires


resolveUserIdentifier :: UserIdentifier -> Transaction (Maybe UserId)
resolveUserIdentifier (UserIdentifier (Just uid) _ _) = return $ Just uid
resolveUserIdentifier (UserIdentifier Nothing (Just name) _) = do
  result <- statement name selectUserIdByName
  case result of
    Nothing -> return Nothing
    Just uuid' -> return $ Just $ UserUUID uuid'
resolveUserIdentifier (UserIdentifier Nothing Nothing (Just email)) = do
  result <- statement email selectUserIdByEmail
  case result of
    Nothing -> return Nothing
    Just uuid' -> return $ Just $ UserUUID uuid'
resolveUserIdentifier (UserIdentifier Nothing Nothing Nothing) = return Nothing


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
      return $ Left $ NotFound $ GroupIdentifier gident
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
      return $ Left $ NotFound $ PolicyIdentifier pident
    Just (PolicyUUID pid) -> do
      result' <- resolvePolicies rest
      case result' of
        Left e -> return $ Left e
        Right pids -> return $ Right $ PolicyUUID pid : pids


loadSession :: UserId -> SessionId -> Transaction (Either Error Session)
loadSession (UserUUID uid) sid = do
  result <- statement (uid, unSessionId sid) selectUserSessionById
  case result of
    Nothing -> return $ Left $ NotFound $ SessionIdentifier $ Just sid
    Just (addr, expires) ->
      return $ Right $ Session sid (IpAddr addr) (UserUUID uid) expires
