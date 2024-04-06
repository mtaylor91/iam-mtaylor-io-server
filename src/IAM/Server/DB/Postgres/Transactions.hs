module IAM.Server.DB.Postgres.Transactions
  ( module IAM.Server.DB.Postgres.Transactions
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.Aeson (Result(..), fromJSON)
import Data.Text (Text)
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
  result0 <- statement email selectUserUUIDByEmail
  case result0 of
    Nothing -> return $ Left NotFound
    Just uuid' -> do
      result1 <- pgGetUser (UserId $ UserUUID uuid')
      case result1 of
        Left e -> return $ Left e
        Right user -> return $ Right $ user { userEmail = Just email }


pgGetUserById :: UserId -> Transaction (Either DBError User)
pgGetUserById (UserUUID uuid) = do
  result <- statement uuid selectUserUUID
  case result of
    Nothing -> return $ Left NotFound
    Just _ -> do
      r0 <- statement uuid selectUserGroups
      r1 <- statement uuid selectUserPolicies
      r2 <- statement uuid selectUserPublicKeys
      let groups = map group $ toList r0
      let publicKeys = map pk $ toList r2
      case mapM fromJSON $ toList r1 of
        Error _ -> return $ Left InternalError
        Success policies ->
          return $ Right $ User (UserUUID uuid) Nothing groups policies publicKeys
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
  statement uuid insertUserUUID

  case maybeEmail of
    Nothing -> return ()
    Just email -> do
      statement (uuid, email) insertUserEmail

  mapM_ insertUserGroup' groups
  mapM_ insertUserPolicy' policies
  mapM_ insertUserPublicKey' publicKeys

  return $ Right $ User (UserUUID uuid) maybeEmail groups policies publicKeys

  where

  insertUserGroup' (GroupId (GroupUUID guuid)) =
    statement (uuid, guuid) insertUserGroup
  insertUserGroup' (GroupIdAndName (GroupUUID guuid) _) =
    statement (uuid, guuid) insertUserGroup
  insertUserGroup' (GroupName name) = do
    result <- statement name selectGroupIdByName
    case result of
      Nothing -> return ()
      Just guuid -> statement (uuid, guuid) insertUserGroup

  insertUserPolicy' pid = statement (uuid, pid) insertUserPolicy

  insertUserPublicKey' (UserPublicKey (PublicKey pk) description) =
    statement (uuid, pk, description) insertUserPublicKey
