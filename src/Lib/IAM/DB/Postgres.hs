{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE QuasiQuotes #-}
module Lib.IAM.DB.Postgres ( connectToDatabase, PostgresDB(..) ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Crypto.Sign.Ed25519
import Data.Aeson (Value, Result(..), fromJSON, toJSON)
import Data.ByteString (ByteString)
import Data.Word (Word16)
import Data.Text (Text)
import Data.UUID (UUID)
import Data.Vector (Vector, toList)
import Hasql.Pool (Pool)
import Hasql.Session (Session, statement)
import Hasql.Statement (Statement)
import Hasql.TH (maybeStatement, resultlessStatement, vectorStatement)
import qualified Hasql.Connection as Connection
import qualified Hasql.Pool as Pool

import Lib.IAM
import Lib.IAM.DB


newtype PostgresDB = PostgresDB Pool


connectToDatabase :: (MonadIO m) =>
  ByteString -> Word16 -> ByteString -> ByteString -> ByteString -> m PostgresDB
connectToDatabase host port database username password = do
  let settings = Connection.settings host port database username password
  pool <- liftIO $ Pool.acquire 3 1800 1800 settings
  return $ PostgresDB pool


useDB :: (MonadIO m, MonadError DBError m) => PostgresDB -> Session a -> m a
useDB (PostgresDB pool) session = do
  result <- liftIO $ Pool.use pool session
  case result of
    Right a -> return a
    Left err -> do
      liftIO $ print err
      throwError InternalError


instance DB PostgresDB where

  getUser db (UserEmail email) = do
    r0 <- useDB db $ statement email selectUserEmail
    case r0 of
      Just _ -> do
        r1 <- useDB db $ statement email selectUserEmailGroupNames
        r2 <- useDB db $ statement email selectUserEmailGroupUUIDs
        r3 <- useDB db $ statement email selectUserEmailPublicKeys
        let gs = namedGroups ++ uuidGroups
            pks = map PublicKey $ toList r3
            uuidGroups = map GroupUUID $ toList r2
            namedGroups = map GroupName $ toList r1
        return $ User (UserEmail email) gs pks
      Nothing -> throwError NotFound
  getUser db (UserUUID uuid) = do
    r0 <- useDB db $ statement uuid selectUserUUIDGroupNames
    r1 <- useDB db $ statement uuid selectUserUUIDGroupUUIDs
    r2 <- useDB db $ statement uuid selectUserUUIDPublicKeys
    let gs = namedGroups ++ uuidGroups
        pks = map PublicKey $ toList r2
        uuidGroups = map GroupUUID $ toList r1
        namedGroups = map GroupName $ toList r0
    return $ User (UserUUID uuid) gs pks

  listUsers db = do
    r0 <- useDB db $ statement () selectUserEmails
    r1 <- useDB db $ statement () selectUserUUIDs
    let userEmails = map UserEmail $ toList r0
        userUUIDs = map UserUUID $ toList r1
    return $ userEmails ++ userUUIDs

  createUser db (UserPrincipal (UserEmail email) pk) = do
    r0 <- useDB db $ statement email selectUserEmail
    case r0 of
      Just _ -> throwError AlreadyExists
      Nothing -> do
        useDB db $ statement email insertUserEmail
        useDB db $ statement (email, unPublicKey pk) insertUserEmailPublicKey
        return $ UserPrincipal (UserEmail email) pk
  createUser db (UserPrincipal (UserUUID uuid) pk) = do
    r0 <- useDB db $ statement uuid selectUserUUID
    case r0 of
      Just _ -> throwError AlreadyExists
      Nothing -> do
        useDB db $ statement uuid insertUserUUID
        useDB db $ statement (uuid, unPublicKey pk) insertUserUUIDPublicKey
        return $ UserPrincipal (UserUUID uuid) pk

  deleteUser db (UserEmail email) = do
    r0 <- useDB db $ statement email selectUserEmail
    case r0 of
      Just _ -> do
        useDB db $ statement email deleteAllUserEmailGroupNames
        useDB db $ statement email deleteAllUserEmailGroupUUIDs
        useDB db $ statement email deleteAllUserEmailPublicKeys
        useDB db $ statement email deleteUserEmail
        return $ UserEmail email
      Nothing -> throwError NotFound
  deleteUser db (UserUUID uuid) = do
    r0 <- useDB db $ statement uuid selectUserUUID
    case r0 of
      Just _ -> do
        useDB db $ statement uuid deleteAllUserUUIDGroupNames
        useDB db $ statement uuid deleteAllUserUUIDGroupUUIDs
        useDB db $ statement uuid deleteAllUserUUIDPublicKeys
        useDB db $ statement uuid deleteUserUUID
        return $ UserUUID uuid
      Nothing -> throwError NotFound

  getGroup db (GroupName name) = do
    r0 <- useDB db $ statement name selectGroupName
    case r0 of
      Just _ -> do
        r1 <- useDB db $ statement name selectGroupNameUserEmails
        r2 <- useDB db $ statement name selectGroupNameUserUUIDs
        let userEmails = map UserEmail $ toList r1
            userUUIDs = map UserUUID $ toList r2
        return $ Group (GroupName name) (userEmails ++ userUUIDs)
      Nothing -> throwError NotFound
  getGroup db (GroupUUID uuid) = do
    r0 <- useDB db $ statement uuid selectGroupUUID
    case r0 of
      Just _ -> do
        r1 <- useDB db $ statement uuid selectGroupUUIDUserEmails
        r2 <- useDB db $ statement uuid selectGroupUUIDUserUUIDs
        let userEmails = map UserEmail $ toList r1
            userUUIDs = map UserUUID $ toList r2
        return $ Group (GroupUUID uuid) (userEmails ++ userUUIDs)
      Nothing -> throwError NotFound

  listGroups db = do
    r0 <- useDB db $ statement () selectGroupNames
    r1 <- useDB db $ statement () selectGroupUUIDs
    let groupNames = map GroupName $ toList r0
        groupUUIDs = map GroupUUID $ toList r1
    return $ groupNames ++ groupUUIDs

  createGroup db (Group (GroupName name) users) = do
    r0 <- useDB db $ statement name selectGroupName
    case r0 of
      Just _ -> throwError AlreadyExists
      Nothing -> do
        useDB db $ statement name insertGroupName
        forM_ users $ \user -> do
          case user of
            UserEmail email -> do
              r1 <- useDB db $ statement email selectUserEmail
              case r1 of
                Just _ -> useDB db $ statement (email, name) insertUserEmailGroupName
                Nothing -> throwError NotFound
            UserUUID uuid -> do
              r1 <- useDB db $ statement uuid selectUserUUID
              case r1 of
                Just _ -> useDB db $ statement (uuid, name) insertUserUUIDGroupName
                Nothing -> throwError NotFound
        return $ Group (GroupName name) users
  createGroup db (Group (GroupUUID uuid) users) = do
    r0 <- useDB db $ statement uuid selectGroupUUID
    case r0 of
      Just _ -> throwError AlreadyExists
      Nothing -> do
        useDB db $ statement uuid insertGroupUUID
        forM_ users $ \user -> do
          case user of
            UserEmail email -> do
              r1 <- useDB db $ statement email selectUserEmail
              case r1 of
                Just _ -> useDB db $ statement (email, uuid) insertUserEmailGroupUUID
                Nothing -> throwError NotFound
            UserUUID uuid' -> do
              r1 <- useDB db $ statement uuid selectUserUUID
              case r1 of
                Just _ -> useDB db $ statement (uuid', uuid) insertUserUUIDGroupUUID
                Nothing -> throwError NotFound
        return $ Group (GroupUUID uuid) users

  deleteGroup db (GroupName name) = do
    r0 <- useDB db $ statement name selectGroupName
    case r0 of
      Just _ -> do
        useDB db $ statement name deleteAllGroupNameUserEmails
        useDB db $ statement name deleteAllGroupNameUserUUIDs
        useDB db $ statement name deleteGroupName
      Nothing -> throwError NotFound
  deleteGroup db (GroupUUID uuid) = do
    r0 <- useDB db $ statement uuid selectGroupUUID
    case r0 of
      Just _ -> do
        useDB db $ statement uuid deleteAllGroupUUIDUserEmails
        useDB db $ statement uuid deleteAllGroupUUIDUserUUIDs
        useDB db $ statement uuid deleteGroupUUID
      Nothing -> throwError NotFound

  getPolicy db uuid = do
    r <- useDB db $ statement uuid selectPolicy
    case r of
      Nothing -> throwError NotFound
      Just policyJSON -> do
        case fromJSON policyJSON of
          Success policy -> return policy
          Error _ -> throwError InternalError

  listPolicies db = do
    r <- useDB db $ statement () selectPolicies
    case mapM fromJSON $ toList r of
      Success policies -> return policies
      Error _ -> throwError InternalError

  listPoliciesForUser db (UserEmail email) = do
    r0 <- useDB db $ statement email selectUserEmail
    case r0 of
      Just _ -> do
        groupNames <- useDB db $ statement email selectUserEmailGroupNames
        groupUUIDs <- useDB db $ statement email selectUserEmailGroupUUIDs
        namedGroupPolicies <- forM groupNames $ \groupName -> do
          r <- useDB db $ statement groupName selectGroupNamePolicies
          return $ toList r
        uuidGroupPolicies <- forM groupUUIDs $ \groupUUID -> do
          r <- useDB db $ statement groupUUID selectGroupUUIDPolicies
          return $ toList r
        let groupPolicies = namedGroupPolicies' ++ uuidGroupPolicies'
            namedGroupPolicies' = toList namedGroupPolicies
            uuidGroupPolicies' = toList uuidGroupPolicies
        userPolicies <- useDB db $ statement email selectUserEmailPolicies
        case mapM fromJSON $ concat groupPolicies ++ toList userPolicies of
          Success policies' -> return policies'
          Error _ -> throwError InternalError
      Nothing -> throwError NotFound
  listPoliciesForUser db (UserUUID uuid) = do
    r0 <- useDB db $ statement uuid selectUserUUID
    case r0 of
      Just _ -> do
        groupNames <- useDB db $ statement uuid selectUserUUIDGroupNames
        groupUUIDs <- useDB db $ statement uuid selectUserUUIDGroupUUIDs
        namedGroupPolicies <- forM groupNames $ \groupName -> do
          r <- useDB db $ statement groupName selectGroupNamePolicies
          return $ toList r
        uuidGroupPolicies <- forM groupUUIDs $ \groupUUID -> do
          r <- useDB db $ statement groupUUID selectGroupUUIDPolicies
          return $ toList r
        let groupPolicies = namedGroupPolicies' ++ uuidGroupPolicies'
            namedGroupPolicies' = toList namedGroupPolicies
            uuidGroupPolicies' = toList uuidGroupPolicies
        userPolicies <- useDB db $ statement uuid selectUserUUIDPolicies
        case mapM fromJSON $ concat groupPolicies ++ toList userPolicies of
          Success policies' -> return policies'
          Error _ -> throwError InternalError
      Nothing -> throwError NotFound

  createPolicy db policy = do
    r0 <- useDB db $ statement (policyId policy) selectPolicy
    case r0 of
      Just _ -> throwError AlreadyExists
      Nothing -> do
        useDB db $ statement (policyId policy, toJSON policy) insertPolicy
        return policy

  updatePolicy db policy = do
    r0 <- useDB db $ statement (policyId policy) selectPolicy
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (policyId policy, toJSON policy) updatePolicy'
        return policy

  deletePolicy db uuid = do
    r0 <- useDB db $ statement uuid selectPolicy
    case r0 of
      Nothing -> throwError NotFound
      Just p -> do
        useDB db $ statement uuid deletePolicyGroupNames
        useDB db $ statement uuid deletePolicyGroupUUIDs
        useDB db $ statement uuid deletePolicyUserEmails
        useDB db $ statement uuid deletePolicyUserUUIDs
        useDB db $ statement uuid deletePolicy'
        case fromJSON p of
          Success policy -> return policy
          Error _ -> throwError InternalError

  createMembership db (UserEmail userEmail) (GroupName groupName) = do
    r0 <- useDB db $ statement groupName selectGroupName
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement userEmail selectUserEmail
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (userEmail, groupName) insertUserEmailGroupName
            return $ Membership (UserEmail userEmail) (GroupName groupName)
  createMembership db (UserUUID userUUID) (GroupName groupName) = do
    r0 <- useDB db $ statement groupName selectGroupName
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement userUUID selectUserUUID
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (userUUID, groupName) insertUserUUIDGroupName
            return $ Membership (UserUUID userUUID) (GroupName groupName)
  createMembership db (UserEmail userEmail) (GroupUUID groupUUID) = do
    r0 <- useDB db $ statement groupUUID selectGroupUUID
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement userEmail selectUserEmail
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (userEmail, groupUUID) insertUserEmailGroupUUID
            return $ Membership (UserEmail userEmail) (GroupUUID groupUUID)
  createMembership db (UserUUID userUUID) (GroupUUID groupUUID) = do
    r0 <- useDB db $ statement groupUUID selectGroupUUID
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement userUUID selectUserUUID
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (userUUID, groupUUID) insertUserUUIDGroupUUID
            return $ Membership (UserUUID userUUID) (GroupUUID groupUUID)

  deleteMembership db (UserEmail userEmail) (GroupName groupName) = do
    r0 <- useDB db $ statement (userEmail, groupName) selectUserEmailGroupName
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (userEmail, groupName) deleteUserEmailGroupName
        return $ Membership (UserEmail userEmail) (GroupName groupName)
  deleteMembership db (UserEmail userEmail) (GroupUUID groupUUID) = do
    r0 <- useDB db $ statement (userEmail, groupUUID) selectUserEmailGroupUUID
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (userEmail, groupUUID) deleteUserEmailGroupUUID
        return $ Membership (UserEmail userEmail) (GroupUUID groupUUID)
  deleteMembership db (UserUUID userUUID) (GroupName groupName) = do
    r0 <- useDB db $ statement (userUUID, groupName) selectUserUUIDGroupName
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (userUUID, groupName) deleteUserUUIDGroupName
        return $ Membership (UserUUID userUUID) (GroupName groupName)
  deleteMembership db (UserUUID userUUID) (GroupUUID groupUUID) = do
    r0 <- useDB db $ statement (userUUID, groupUUID) selectUserUUIDGroupUUID
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (userUUID, groupUUID) deleteUserUUIDGroupUUID
        return $ Membership (UserUUID userUUID) (GroupUUID groupUUID)

  createUserPolicyAttachment db (UserEmail userEmail) policyUUID = do
    r0 <- useDB db $ statement userEmail selectUserEmail
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement policyUUID selectPolicy
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (userEmail, policyUUID) insertUserEmailPolicy
            return $ UserPolicyAttachment (UserEmail userEmail) policyUUID
  createUserPolicyAttachment db (UserUUID userUUID) policyUUID = do
    r0 <- useDB db $ statement userUUID selectUserUUID
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement policyUUID selectPolicy
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (userUUID, policyUUID) insertUserUUIDPolicy
            return $ UserPolicyAttachment (UserUUID userUUID) policyUUID

  deleteUserPolicyAttachment db (UserEmail userEmail) policyUUID = do
    r0 <- useDB db $ statement (userEmail, policyUUID) selectUserEmailPolicy
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (userEmail, policyUUID) deleteUserEmailPolicy
        return $ UserPolicyAttachment (UserEmail userEmail) policyUUID
  deleteUserPolicyAttachment db (UserUUID userUUID) policyUUID = do
    r0 <- useDB db $ statement (userUUID, policyUUID) selectUserUUIDPolicy
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (userUUID, policyUUID) deleteUserUUIDPolicy
        return $ UserPolicyAttachment (UserUUID userUUID) policyUUID

  createGroupPolicyAttachment db (GroupName groupName) policyUUID = do
    r0 <- useDB db $ statement groupName selectGroupName
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement policyUUID selectPolicy
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (groupName, policyUUID) insertGroupNamePolicy
            return $ GroupPolicyAttachment (GroupName groupName) policyUUID
  createGroupPolicyAttachment db (GroupUUID groupUUID) policyUUID = do
    r0 <- useDB db $ statement groupUUID selectGroupUUID
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        r1 <- useDB db $ statement policyUUID selectPolicy
        case r1 of
          Nothing -> throwError NotFound
          Just _ -> do
            useDB db $ statement (groupUUID, policyUUID) insertGroupUUIDPolicy
            return $ GroupPolicyAttachment (GroupUUID groupUUID) policyUUID

  deleteGroupPolicyAttachment db (GroupName groupName) policyUUID = do
    r0 <- useDB db $ statement (groupName, policyUUID) selectGroupNamePolicy
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (groupName, policyUUID) deleteGroupNamePolicy
        return $ GroupPolicyAttachment (GroupName groupName) policyUUID
  deleteGroupPolicyAttachment db (GroupUUID groupUUID) policyUUID = do
    r0 <- useDB db $ statement (groupUUID, policyUUID) selectGroupUUIDPolicy
    case r0 of
      Nothing -> throwError NotFound
      Just _ -> do
        useDB db $ statement (groupUUID, policyUUID) deleteGroupUUIDPolicy
        return $ GroupPolicyAttachment (GroupUUID groupUUID) policyUUID


insertUserEmail :: Statement Text ()
insertUserEmail =
  [resultlessStatement|
    INSERT INTO
      user_emails (user_email)
    VALUES
      ($1 :: text)
  |]


insertUserUUID :: Statement UUID ()
insertUserUUID =
  [resultlessStatement|
    INSERT INTO
      user_uuids (user_uuid)
    VALUES
      ($1 :: uuid)
  |]


insertGroupName :: Statement Text ()
insertGroupName =
  [resultlessStatement|
    INSERT INTO
      group_names (group_name)
    VALUES
      ($1 :: text)
  |]


insertGroupUUID :: Statement UUID ()
insertGroupUUID =
  [resultlessStatement|
    INSERT INTO
      group_uuids (group_uuid)
    VALUES
      ($1 :: uuid)
  |]


insertPolicy :: Statement (UUID, Value) ()
insertPolicy =
  [resultlessStatement|
    INSERT INTO
      policies (policy_uuid, policy)
    VALUES
      ($1 :: uuid, $2 :: json)
  |]


insertUserEmailGroupName :: Statement (Text, Text) ()
insertUserEmailGroupName =
  [resultlessStatement|
    INSERT INTO
      user_email_group_names (user_email, group_name)
    VALUES
      ($1 :: text, $2 :: text)
  |]


insertUserUUIDGroupName :: Statement (UUID, Text) ()
insertUserUUIDGroupName =
  [resultlessStatement|
    INSERT INTO
      user_uuid_group_names (user_uuid, group_name)
    VALUES
      ($1 :: uuid, $2 :: text)
  |]


insertUserEmailGroupUUID :: Statement (Text, UUID) ()
insertUserEmailGroupUUID =
  [resultlessStatement|
    INSERT INTO
      user_email_group_uuids (user_email, group_uuid)
    VALUES
      ($1 :: text, $2 :: uuid)
  |]


insertUserUUIDGroupUUID :: Statement (UUID, UUID) ()
insertUserUUIDGroupUUID =
  [resultlessStatement|
    INSERT INTO
      user_uuid_group_uuids (user_uuid, group_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertUserEmailPublicKey :: Statement (Text, ByteString) ()
insertUserEmailPublicKey =
  [resultlessStatement|
    INSERT INTO
      user_email_public_keys (user_email, public_key)
    VALUES
      ($1 :: text, $2 :: bytea)
  |]


insertUserUUIDPublicKey :: Statement (UUID, ByteString) ()
insertUserUUIDPublicKey =
  [resultlessStatement|
    INSERT INTO
      user_uuid_public_keys (user_uuid, public_key)
    VALUES
      ($1 :: uuid, $2 :: bytea)
  |]


insertUserEmailPolicy :: Statement (Text, UUID) ()
insertUserEmailPolicy =
  [resultlessStatement|
    INSERT INTO
      user_email_policies (user_email, policy_uuid)
    VALUES
      ($1 :: text, $2 :: uuid)
  |]


insertUserUUIDPolicy :: Statement (UUID, UUID) ()
insertUserUUIDPolicy =
  [resultlessStatement|
    INSERT INTO
      user_uuid_policies (user_uuid, policy_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertGroupNamePolicy :: Statement (Text, UUID) ()
insertGroupNamePolicy =
  [resultlessStatement|
    INSERT INTO
      group_name_policies (group_name, policy_uuid)
    VALUES
      ($1 :: text, $2 :: uuid)
  |]


insertGroupUUIDPolicy :: Statement (UUID, UUID) ()
insertGroupUUIDPolicy =
  [resultlessStatement|
    INSERT INTO
      group_uuid_policies (group_uuid, policy_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


selectUserEmails :: Statement () (Vector Text)
selectUserEmails =
  [vectorStatement|
    SELECT
      user_emails.user_email :: text
    FROM
      user_emails
  |]


selectUserUUIDs :: Statement () (Vector UUID)
selectUserUUIDs =
  [vectorStatement|
    SELECT
      user_uuids.user_uuid :: uuid
    FROM
      user_uuids
  |]


selectGroupNames :: Statement () (Vector Text)
selectGroupNames =
  [vectorStatement|
    SELECT
      group_names.group_name :: text
    FROM
      group_names
  |]


selectGroupUUIDs :: Statement () (Vector UUID)
selectGroupUUIDs =
  [vectorStatement|
    SELECT
      group_uuids.group_uuid :: uuid
    FROM
      group_uuids
  |]


selectPolicies :: Statement () (Vector Value)
selectPolicies =
  [vectorStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
  |]


selectUserEmail :: Statement Text (Maybe Text)
selectUserEmail =
  [maybeStatement|
    SELECT DISTINCT
      user_emails.user_email :: text
    FROM
      user_emails
    WHERE
      user_emails.user_email = $1 :: text
  |]


selectUserUUID :: Statement UUID (Maybe UUID)
selectUserUUID =
  [maybeStatement|
    SELECT DISTINCT
      user_uuids.user_uuid :: uuid
    FROM
      user_uuids
    WHERE
      user_uuids.user_uuid = $1 :: uuid
  |]


selectGroupName :: Statement Text (Maybe Text)
selectGroupName =
  [maybeStatement|
    SELECT DISTINCT
      group_names.group_name :: text
    FROM
      group_names
    WHERE
      group_names.group_name = $1 :: text
  |]


selectGroupUUID :: Statement UUID (Maybe UUID)
selectGroupUUID =
  [maybeStatement|
    SELECT DISTINCT
      group_uuids.group_uuid :: uuid
    FROM
      group_uuids
    WHERE
      group_uuids.group_uuid = $1 :: uuid
  |]


selectPolicy :: Statement UUID (Maybe Value)
selectPolicy =
  [maybeStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    WHERE
      policies.policy_uuid = $1 :: uuid
  |]


selectUserEmailGroupName :: Statement (Text, Text) (Maybe (Text, Text))
selectUserEmailGroupName =
  [maybeStatement|
    SELECT
      user_email_group_names.user_email :: text,
      user_email_group_names.group_name :: text
    FROM
      user_email_group_names
    WHERE
      user_email_group_names.user_email = $1 :: text
      AND
      user_email_group_names.group_name = $2 :: text
  |]


selectUserEmailGroupNames :: Statement Text (Vector Text)
selectUserEmailGroupNames =
  [vectorStatement|
    SELECT DISTINCT
      user_email_group_names.group_name :: text
    FROM
      user_email_group_names
    WHERE
      user_email_group_names.user_email = $1 :: text
  |]


selectUserEmailGroupUUID :: Statement (Text, UUID) (Maybe (Text, UUID))
selectUserEmailGroupUUID =
  [maybeStatement|
    SELECT
      user_email_group_uuids.user_email :: text,
      user_email_group_uuids.group_uuid :: uuid
    FROM
      user_email_group_uuids
    WHERE
      user_email_group_uuids.user_email = $1 :: text
      AND
      user_email_group_uuids.group_uuid = $2 :: uuid
  |]

selectUserEmailGroupUUIDs :: Statement Text (Vector UUID)
selectUserEmailGroupUUIDs =
  [vectorStatement|
    SELECT DISTINCT
      user_email_group_uuids.group_uuid :: uuid
    FROM
      user_email_group_uuids
    WHERE
      user_email_group_uuids.user_email = $1 :: text
  |]


selectUserUUIDGroupName :: Statement (UUID, Text) (Maybe (UUID, Text))
selectUserUUIDGroupName =
  [maybeStatement|
    SELECT
      user_uuid_group_names.user_uuid :: uuid,
      user_uuid_group_names.group_name :: text
    FROM
      user_uuid_group_names
    WHERE
      user_uuid_group_names.user_uuid = $1 :: uuid
      AND
      user_uuid_group_names.group_name = $2 :: text
  |]


selectUserUUIDGroupNames :: Statement UUID (Vector Text)
selectUserUUIDGroupNames =
  [vectorStatement|
    SELECT DISTINCT
      user_uuid_group_names.group_name :: text
    FROM
      user_uuid_group_names
    WHERE
      user_uuid_group_names.user_uuid = $1 :: uuid
  |]


selectUserUUIDGroupUUID :: Statement (UUID, UUID) (Maybe (UUID, UUID))
selectUserUUIDGroupUUID =
  [maybeStatement|
    SELECT
      user_uuid_group_uuids.user_uuid :: uuid,
      user_uuid_group_uuids.group_uuid :: uuid
    FROM
      user_uuid_group_uuids
    WHERE
      user_uuid_group_uuids.user_uuid = $1 :: uuid
      AND
      user_uuid_group_uuids.group_uuid = $2 :: uuid
  |]


selectUserUUIDGroupUUIDs :: Statement UUID (Vector UUID)
selectUserUUIDGroupUUIDs =
  [vectorStatement|
    SELECT DISTINCT
      user_uuid_group_uuids.group_uuid :: uuid
    FROM
      user_uuid_group_uuids
    WHERE
      user_uuid_group_uuids.user_uuid = $1 :: uuid
  |]


selectUserEmailPublicKeys :: Statement Text (Vector ByteString)
selectUserEmailPublicKeys =
  [vectorStatement|
    SELECT
      user_email_public_keys.public_key :: bytea
    FROM
      user_email_public_keys
    WHERE
      user_email_public_keys.user_email = $1 :: text
  |]


selectUserUUIDPublicKeys :: Statement UUID (Vector ByteString)
selectUserUUIDPublicKeys =
  [vectorStatement|
    SELECT
      user_uuid_public_keys.public_key :: bytea
    FROM
      user_uuid_public_keys
    WHERE
      user_uuid_public_keys.user_uuid = $1 :: uuid
  |]


selectGroupNamePolicy :: Statement (Text, UUID) (Maybe Value)
selectGroupNamePolicy =
  [maybeStatement|
    SELECT
      group_name_policies.policy :: json
    FROM
      group_name_policies
    WHERE
      group_name_policies.group_name = $1 :: text
      AND
      group_name_policies.policy_uuid = $2 :: uuid
  |]


selectGroupUUIDPolicy :: Statement (UUID, UUID) (Maybe Value)
selectGroupUUIDPolicy =
  [maybeStatement|
    SELECT
      group_uuid_policies.policy :: json
    FROM
      group_uuid_policies
    WHERE
      group_uuid_policies.group_uuid = $1 :: uuid
      AND
      group_uuid_policies.policy_uuid = $2 :: uuid
  |]


selectGroupNameUserEmails :: Statement Text (Vector Text)
selectGroupNameUserEmails =
  [vectorStatement|
    SELECT DISTINCT
      user_email_group_names.user_email :: text
    FROM
      user_email_group_names
    WHERE
      user_email_group_names.group_name = $1 :: text
  |]


selectGroupNameUserUUIDs :: Statement Text (Vector UUID)
selectGroupNameUserUUIDs =
  [vectorStatement|
    SELECT DISTINCT
      user_uuid_group_names.user_uuid :: uuid
    FROM
      user_uuid_group_names
    WHERE
      user_uuid_group_names.group_name = $1 :: text
  |]


selectGroupUUIDUserEmails :: Statement UUID (Vector Text)
selectGroupUUIDUserEmails =
  [vectorStatement|
    SELECT DISTINCT
      user_email_group_uuids.user_email :: text
    FROM
      user_email_group_uuids
    WHERE
      user_email_group_uuids.group_uuid = $1 :: uuid
  |]


selectGroupUUIDUserUUIDs :: Statement UUID (Vector UUID)
selectGroupUUIDUserUUIDs =
  [vectorStatement|
    SELECT DISTINCT
      user_uuid_group_uuids.user_uuid :: uuid
    FROM
      user_uuid_group_uuids
    WHERE
      user_uuid_group_uuids.group_uuid = $1 :: uuid
  |]


selectUserEmailPolicy :: Statement (Text, UUID) (Maybe Value)
selectUserEmailPolicy =
  [maybeStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    INNER JOIN
      user_email_policies
    ON
      policies.policy_uuid = user_email_policies.policy_uuid
    WHERE
      user_email_policies.user_email = $1 :: text
      AND
      user_email_policies.policy_uuid = $2 :: uuid
  |]


selectUserUUIDPolicy :: Statement (UUID, UUID) (Maybe Value)
selectUserUUIDPolicy =
  [maybeStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    INNER JOIN
      user_uuid_policies
    ON
      policies.policy_uuid = user_uuid_policies.policy_uuid
    WHERE
      user_uuid_policies.user_uuid = $1 :: uuid
      AND
      user_uuid_policies.policy_uuid = $2 :: uuid
  |]


selectUserEmailPolicies :: Statement Text (Vector Value)
selectUserEmailPolicies =
  [vectorStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    INNER JOIN
      user_email_policies
    ON
      policies.policy_uuid = user_email_policies.policy_uuid
    WHERE
      user_email_policies.user_email = $1 :: text
  |]


selectUserUUIDPolicies :: Statement UUID (Vector Value)
selectUserUUIDPolicies =
  [vectorStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    INNER JOIN
      user_uuid_policies
    ON
      policies.policy_uuid = user_uuid_policies.policy_uuid
    WHERE
      user_uuid_policies.user_uuid = $1 :: uuid
  |]


selectGroupNamePolicies :: Statement Text (Vector Value)
selectGroupNamePolicies =
  [vectorStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    INNER JOIN
      group_name_policies
    ON
      policies.policy_uuid = group_name_policies.policy_uuid
    WHERE
      group_name_policies.group_name = $1 :: text
  |]


selectGroupUUIDPolicies :: Statement UUID (Vector Value)
selectGroupUUIDPolicies =
  [vectorStatement|
    SELECT
      policies.policy :: json
    FROM
      policies
    INNER JOIN
      group_uuid_policies
    ON
      policies.policy_uuid = group_uuid_policies.policy_uuid
    WHERE
      group_uuid_policies.group_uuid = $1 :: uuid
  |]


updatePolicy' :: Statement (UUID, Value) ()
updatePolicy' =
  [resultlessStatement|
    UPDATE
      policies
    SET
      policy = $2 :: json
    WHERE
      policy_uuid = $1 :: uuid
  |]


deleteUserEmail :: Statement Text ()
deleteUserEmail =
  [resultlessStatement|
    DELETE FROM
      user_emails
    WHERE
      user_email = $1 :: text
  |]


deleteUserUUID :: Statement UUID ()
deleteUserUUID =
  [resultlessStatement|
    DELETE FROM
      user_uuids
    WHERE
      user_uuid = $1 :: uuid
  |]


deleteGroupName :: Statement Text ()
deleteGroupName =
  [resultlessStatement|
    DELETE FROM
      group_names
    WHERE
      group_name = $1 :: text
  |]


deleteGroupUUID :: Statement UUID ()
deleteGroupUUID =
  [resultlessStatement|
    DELETE FROM
      group_uuids
    WHERE
      group_uuid = $1 :: uuid
  |]


deletePolicy' :: Statement UUID ()
deletePolicy' =
  [resultlessStatement|
    DELETE FROM
      policies
    WHERE
      policy_uuid = $1 :: uuid
  |]


deleteAllUserEmailGroupNames :: Statement Text ()
deleteAllUserEmailGroupNames =
  [resultlessStatement|
    DELETE FROM
      user_email_group_names
    WHERE
      user_email = $1 :: text
  |]


deleteAllUserEmailGroupUUIDs :: Statement Text ()
deleteAllUserEmailGroupUUIDs =
  [resultlessStatement|
    DELETE FROM
      user_email_group_uuids
    WHERE
      user_email = $1 :: text
  |]


deleteAllUserUUIDGroupNames :: Statement UUID ()
deleteAllUserUUIDGroupNames =
  [resultlessStatement|
    DELETE FROM
      user_uuid_group_names
    WHERE
      user_uuid = $1 :: uuid
  |]


deleteAllUserUUIDGroupUUIDs :: Statement UUID ()
deleteAllUserUUIDGroupUUIDs =
  [resultlessStatement|
    DELETE FROM
      user_uuid_group_uuids
    WHERE
      user_uuid = $1 :: uuid
  |]


deleteAllGroupNameUserEmails :: Statement Text ()
deleteAllGroupNameUserEmails =
  [resultlessStatement|
    DELETE FROM
      user_email_group_names
    WHERE
      group_name = $1 :: text
  |]


deleteAllGroupNameUserUUIDs :: Statement Text ()
deleteAllGroupNameUserUUIDs =
  [resultlessStatement|
    DELETE FROM
      user_uuid_group_names
    WHERE
      group_name = $1 :: text
  |]


deleteAllGroupUUIDUserEmails :: Statement UUID ()
deleteAllGroupUUIDUserEmails =
  [resultlessStatement|
    DELETE FROM
      user_email_group_uuids
    WHERE
      group_uuid = $1 :: uuid
  |]


deleteAllGroupUUIDUserUUIDs :: Statement UUID ()
deleteAllGroupUUIDUserUUIDs =
  [resultlessStatement|
    DELETE FROM
      user_uuid_group_uuids
    WHERE
      group_uuid = $1 :: uuid
  |]


deleteAllUserEmailPublicKeys :: Statement Text ()
deleteAllUserEmailPublicKeys =
  [resultlessStatement|
    DELETE FROM
      user_email_public_keys
    WHERE
      user_email = $1 :: text
  |]


deleteAllUserUUIDPublicKeys :: Statement UUID ()
deleteAllUserUUIDPublicKeys =
  [resultlessStatement|
    DELETE FROM
      user_uuid_public_keys
    WHERE
      user_uuid = $1 :: uuid
  |]


deleteUserEmailGroupName :: Statement (Text, Text) ()
deleteUserEmailGroupName =
  [resultlessStatement|
    DELETE FROM
      user_email_group_names
    WHERE
      user_email = $1 :: text
    AND
      group_name = $2 :: text
  |]


deleteUserEmailGroupUUID :: Statement (Text, UUID) ()
deleteUserEmailGroupUUID =
  [resultlessStatement|
    DELETE FROM
      user_email_group_uuids
    WHERE
      user_email = $1 :: text
    AND
      group_uuid = $2 :: uuid
  |]


deleteUserUUIDGroupName :: Statement (UUID, Text) ()
deleteUserUUIDGroupName =
  [resultlessStatement|
    DELETE FROM
      user_uuid_group_names
    WHERE
      user_uuid = $1 :: uuid
    AND
      group_name = $2 :: text
  |]


deleteUserUUIDGroupUUID :: Statement (UUID, UUID) ()
deleteUserUUIDGroupUUID =
  [resultlessStatement|
    DELETE FROM
      user_uuid_group_uuids
    WHERE
      user_uuid = $1 :: uuid
    AND
      group_uuid = $2 :: uuid
  |]


deleteGroupNamePolicy :: Statement (Text, UUID) ()
deleteGroupNamePolicy =
  [resultlessStatement|
    DELETE FROM
      group_name_policies
    WHERE
      group_name = $1 :: text
    AND
      policy_uuid = $2 :: uuid
  |]


deleteGroupUUIDPolicy :: Statement (UUID, UUID) ()
deleteGroupUUIDPolicy =
  [resultlessStatement|
    DELETE FROM
      group_uuid_policies
    WHERE
      group_uuid = $1 :: uuid
    AND
      policy_uuid = $2 :: uuid
  |]


deletePolicyGroupNames :: Statement UUID ()
deletePolicyGroupNames =
  [resultlessStatement|
    DELETE FROM
      group_name_policies
    WHERE
      policy_uuid = $1 :: uuid
  |]


deletePolicyGroupUUIDs :: Statement UUID ()
deletePolicyGroupUUIDs =
  [resultlessStatement|
    DELETE FROM
      group_uuid_policies
    WHERE
      policy_uuid = $1 :: uuid
  |]


deletePolicyUserEmails :: Statement UUID ()
deletePolicyUserEmails =
  [resultlessStatement|
    DELETE FROM
      user_email_policies
    WHERE
      policy_uuid = $1 :: uuid
  |]


deletePolicyUserUUIDs :: Statement UUID ()
deletePolicyUserUUIDs =
  [resultlessStatement|
    DELETE FROM
      user_uuid_policies
    WHERE
      policy_uuid = $1 :: uuid
  |]


deleteUserEmailPolicy :: Statement (Text, UUID) ()
deleteUserEmailPolicy =
  [resultlessStatement|
    DELETE FROM
      user_email_policies
    WHERE
      user_email = $1 :: text
    AND
      policy_uuid = $2 :: uuid
  |]


deleteUserUUIDPolicy :: Statement (UUID, UUID) ()
deleteUserUUIDPolicy =
  [resultlessStatement|
    DELETE FROM
      user_uuid_policies
    WHERE
      user_uuid = $1 :: uuid
    AND
      policy_uuid = $2 :: uuid
  |]
