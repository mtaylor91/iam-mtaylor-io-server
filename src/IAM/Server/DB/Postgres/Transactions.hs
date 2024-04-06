module IAM.Server.DB.Postgres.Transactions
  ( module IAM.Server.DB.Postgres.Transactions
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.Aeson (Result(..), fromJSON)
import Data.Text (Text)
import Data.UUID (UUID)
import Data.Vector (toList)
import Hasql.Transaction (Transaction, statement)

import IAM.Server.DB
import IAM.Server.DB.Postgres.Queries
import IAM.Types


pgGetUser :: UserIdentifier -> Transaction (Either DBError User)
pgGetUser userIdentifier =
  case unUserIdentifier userIdentifier of
    Left email -> pgGetUserByEmail email
    Right (UserUUID uuid) -> pgGetUserById $ UserUUID uuid


pgGetUserByEmail :: Text -> Transaction (Either DBError User)
pgGetUserByEmail email = do
  result0 <- statement email selectUserIdByEmail
  case result0 of
    Nothing -> return $ Left NotFound
    Just uuid' -> do
      pgGetUser (UserId $ UserUUID uuid')


pgGetUserById :: UserId -> Transaction (Either DBError User)
pgGetUserById (UserUUID uuid) = do
  result <- statement uuid selectUserId
  case result of
    Nothing -> return $ Left NotFound
    Just _ -> do
      maybeEmail <- statement uuid selectUserEmail
      r0 <- statement uuid selectUserGroups
      r1 <- statement uuid selectUserPolicies
      r2 <- statement uuid selectUserPublicKeys
      let groups = map group $ toList r0
      let publicKeys = map pk $ toList r2
      case mapM fromJSON $ toList r1 of
        Error _ -> return $ Left InternalError
        Success policies ->
          return $ Right $ User (UserUUID uuid) maybeEmail groups policies publicKeys
  where
    group (guuid, Nothing) = GroupId $ GroupUUID guuid
    group (guuid, Just name) = GroupIdAndName (GroupUUID guuid) name
    pk (pkBytes, pkDescription) = UserPublicKey (PublicKey pkBytes) pkDescription


pgListUsers :: Range -> Transaction (Either DBError [UserId])
pgListUsers (Range offset Nothing) = pgListUsers (Range offset $ Just 100)
pgListUsers (Range offset (Just limit)) = do
  result <- statement (fromIntegral offset, fromIntegral limit) selectUserIds
  return $ Right $ map UserUUID $ toList result


pgCreateUser :: User -> Transaction (Either DBError User)
pgCreateUser (User (UserUUID uuid) maybeEmail groups policies publicKeys) = do
  statement uuid insertUserId

  case maybeEmail of
    Nothing -> return ()
    Just email -> do
      statement (uuid, email) insertUserEmail

  result <- resolveUserGroups groups
  case result of
    Left e -> return $ Left e
    Right gids -> do
      mapM_ insertUserGroup' gids
      mapM_ insertUserPolicy' policies
      mapM_ insertUserPublicKey' publicKeys

      return $ Right $ User (UserUUID uuid) maybeEmail groups policies publicKeys

  where

  insertUserGroup' :: GroupId -> Transaction ()
  insertUserGroup' (GroupUUID guuid) = statement (uuid, guuid) insertUserGroup

  insertUserPolicy' :: UUID -> Transaction ()
  insertUserPolicy' pid = statement (uuid, pid) insertUserPolicy

  insertUserPublicKey' :: UserPublicKey -> Transaction ()
  insertUserPublicKey' (UserPublicKey (PublicKey pk) description) =
    statement (uuid, pk, description) insertUserPublicKey

  resolveUserGroups :: [GroupIdentifier] -> Transaction (Either DBError [GroupId])
  resolveUserGroups [] = return $ Right []
  resolveUserGroups (gident:rest) =
    case unGroupIdentifier gident of
      Left name -> do
        result <- statement name selectGroupIdByName
        case result of
          Nothing -> return $ Left NotFound
          Just guuid -> do
            result' <- resolveUserGroups rest
            case result' of
              Left e -> return $ Left e
              Right gids -> return $ Right $ GroupUUID guuid : gids
      Right (GroupUUID guuid) -> do
        result <- resolveUserGroups rest
        case result of
          Left e -> return $ Left e
          Right gids -> return $ Right $ GroupUUID guuid : gids


pgDeleteUser :: UserIdentifier -> Transaction (Either DBError User)
pgDeleteUser userIdentifier = do
  case unUserIdentifier userIdentifier of
    Left email -> pgDeleteUserByEmail email
    Right (UserUUID uuid) -> pgDeleteUserById $ UserUUID uuid


pgDeleteUserByEmail :: Text -> Transaction (Either DBError User)
pgDeleteUserByEmail email = do
  result0 <- statement email selectUserIdByEmail
  case result0 of
    Nothing -> return $ Left NotFound
    Just uuid' -> pgDeleteUserById $ UserUUID uuid'


pgDeleteUserById :: UserId -> Transaction (Either DBError User)
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


pgGetGroup :: GroupIdentifier -> Transaction (Either DBError Group)
pgGetGroup groupIdentifier =
  case unGroupIdentifier groupIdentifier of
    Left name -> pgGetGroupByName name
    Right (GroupUUID uuid) -> pgGetGroupById $ GroupUUID uuid


pgGetGroupByName :: Text -> Transaction (Either DBError Group)
pgGetGroupByName name = do
  result0 <- statement name selectGroupIdByName
  case result0 of
    Nothing -> return $ Left NotFound
    Just uuid' -> pgGetGroupById $ GroupUUID uuid'


pgGetGroupById :: GroupId -> Transaction (Either DBError Group)
pgGetGroupById (GroupUUID uuid) = do
  result <- statement uuid selectGroupId
  case result of
    Nothing -> return $ Left NotFound
    Just _ -> do
      maybeName <- statement uuid selectGroupName
      r0 <- statement uuid selectGroupUsers
      policies <- toList <$> statement uuid selectGroupPolicyIds
      let users = map user $ toList r0
      return $ Right $ Group (GroupUUID uuid) maybeName users policies
  where
    user (uuuid, Nothing) = UserId $ UserUUID uuuid
    user (uuuid, Just email) = UserIdAndEmail (UserUUID uuuid) email


pgListGroups :: Transaction (Either DBError [GroupId])
pgListGroups = do
  result <- statement () selectGroupIds
  return $ Right $ map GroupUUID $ toList result


pgCreateGroup :: Group -> Transaction (Either DBError Group)
pgCreateGroup (Group (GroupUUID uuid) maybeName users policies) = do
  statement uuid insertGroupId

  case maybeName of
    Nothing -> return ()
    Just name -> do
      statement (uuid, name) insertGroupName

  result <- resolveGroupUsers users
  case result of
    Left e -> return $ Left e
    Right uids -> do
      mapM_ insertGroupUser' uids
      mapM_ insertGroupPolicy' policies

      return $ Right $ Group (GroupUUID uuid) maybeName users policies

  where

  insertGroupUser' :: UserId -> Transaction ()
  insertGroupUser' (UserUUID uuuid) = statement (uuid, uuuid) insertGroupUser

  insertGroupPolicy' :: UUID -> Transaction ()
  insertGroupPolicy' pid = statement (uuid, pid) insertGroupPolicy

  resolveGroupUsers :: [UserIdentifier] -> Transaction (Either DBError [UserId])
  resolveGroupUsers [] = return $ Right []
  resolveGroupUsers (uident:rest) =
    case unUserIdentifier uident of
      Left email -> do
        result <- statement email selectUserIdByEmail
        case result of
          Nothing -> return $ Left NotFound
          Just uuuid -> do
            result' <- resolveGroupUsers rest
            case result' of
              Left e -> return $ Left e
              Right uids -> return $ Right $ UserUUID uuuid : uids
      Right (UserUUID uuuid) -> do
        result <- resolveGroupUsers rest
        case result of
          Left e -> return $ Left e
          Right uids -> return $ Right $ UserUUID uuuid : uids


pgDeleteGroup :: GroupIdentifier -> Transaction (Either DBError Group)
pgDeleteGroup groupIdentifier = do
  case unGroupIdentifier groupIdentifier of
    Left name -> pgDeleteGroupByName name
    Right (GroupUUID uuid) -> pgDeleteGroupById $ GroupUUID uuid


pgDeleteGroupByName :: Text -> Transaction (Either DBError Group)
pgDeleteGroupByName name = do
  result0 <- statement name selectGroupIdByName
  case result0 of
    Nothing -> return $ Left NotFound
    Just uuid' -> pgDeleteGroupById $ GroupUUID uuid'


pgDeleteGroupById :: GroupId -> Transaction (Either DBError Group)
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


pgGetPolicy :: UUID -> Transaction (Either DBError Policy)
pgGetPolicy pid = do
  result <- statement pid selectPolicy
  case result of
    Nothing -> return $ Left NotFound
    Just policy ->
      case fromJSON policy of
        Error _ -> return $ Left InternalError
        Success p -> return $ Right p


pgListPolicies :: Transaction (Either DBError [UUID])
pgListPolicies = do
  result <- statement () selectPolicyIds
  return $ Right $ toList result


pgListPoliciesForUser :: UserId -> Transaction (Either DBError [Policy])
pgListPoliciesForUser (UserUUID uuid) = do
  r0 <- statement uuid selectUserPolicies
  r1 <- statement uuid selectUserGroups
  let groups = map group $ toList r1
  case mapM fromJSON $ toList r0 of
    Error _ -> return $ Left InternalError
    Success ups -> do
      r2 <- mapM pgListPoliciesForGroup groups
      case sequence r2 of
        Left e -> return $ Left e
        Right gps -> return $ Right $ ups ++ concat gps
  where
    group (guuid, _) = GroupId $ GroupUUID guuid


pgListPoliciesForGroup :: GroupIdentifier -> Transaction (Either DBError [Policy])
pgListPoliciesForGroup groupIdentifier = do
  case unGroupIdentifier groupIdentifier of
    Left name -> pgListPoliciesForGroupByName name
    Right (GroupUUID uuid) -> pgListPoliciesForGroupById $ GroupUUID uuid


pgListPoliciesForGroupByName :: Text -> Transaction (Either DBError [Policy])
pgListPoliciesForGroupByName name = do
  result0 <- statement name selectGroupIdByName
  case result0 of
    Nothing -> return $ Left NotFound
    Just uuid' -> pgListPoliciesForGroupById $ GroupUUID uuid'


pgListPoliciesForGroupById :: GroupId -> Transaction (Either DBError [Policy])
pgListPoliciesForGroupById (GroupUUID uuid) = do
  r0 <- statement uuid selectGroupPolicies
  case mapM fromJSON $ toList r0 of
    Error _ -> return $ Left InternalError
    Success policies -> return $ Right policies
