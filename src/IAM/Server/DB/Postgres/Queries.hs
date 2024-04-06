{-# LANGUAGE QuasiQuotes #-}
module IAM.Server.DB.Postgres.Queries
  ( module IAM.Server.DB.Postgres.Queries
  ) where

import Data.Aeson (Value)
import Data.ByteString (ByteString)
import Data.Int (Int32)
import Data.Text (Text)
import Data.UUID (UUID)
import Data.Vector (Vector)
import Hasql.Statement (Statement)
import Hasql.TH (maybeStatement, resultlessStatement, vectorStatement)


insertUserUUID :: Statement UUID ()
insertUserUUID =
  [resultlessStatement|
    INSERT INTO
      users (user_uuid)
    VALUES
      ($1 :: uuid)
  |]


insertUserEmail :: Statement (UUID, Text) ()
insertUserEmail =
  [resultlessStatement|
    INSERT INTO
      users_emails (user_uuid, user_email)
    VALUES
      ($1 :: uuid, $2 :: text)
  |]


insertUserGroup :: Statement (UUID, UUID) ()
insertUserGroup =
  [resultlessStatement|
    INSERT INTO
      users_groups (user_uuid, group_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertUserPolicy :: Statement (UUID, UUID) ()
insertUserPolicy =
  [resultlessStatement|
    INSERT INTO
      users_policies (user_uuid, policy_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertUserPublicKey :: Statement (UUID, ByteString, Text) ()
insertUserPublicKey =
  [resultlessStatement|
    INSERT INTO
      users_public_keys (user_uuid, public_key, description)
    VALUES
      ($1 :: uuid, $2 :: bytea, $3 :: text)
  |]


selectUserUUID :: Statement UUID (Maybe UUID)
selectUserUUID =
  [maybeStatement|
    SELECT DISTINCT
      users.user_uuid :: uuid
    FROM
      users
    WHERE
      users.user_uuid = $1 :: uuid
  |]


selectUserUUIDByEmail :: Statement Text (Maybe UUID)
selectUserUUIDByEmail =
  [maybeStatement|
    SELECT
      users_emails.user_uuid :: uuid
    FROM
      users_emails
    WHERE
      users_emails.user_email = $1 :: text
  |]


selectUserIds :: Statement (Int32, Int32) (Vector UUID)
selectUserIds =
  [vectorStatement|
    SELECT
      users.user_uuid :: uuid
    FROM
      users
    LIMIT
      $1 :: int
    OFFSET
      $2 :: int
  |]


selectUserGroups :: Statement UUID (Vector (UUID, Maybe Text))
selectUserGroups =
  [vectorStatement|
    SELECT
      groups.group_uuid :: uuid,
      groups_names.group_name :: text?
    FROM
      groups
    LEFT JOIN
      groups_names
    ON
      groups.group_uuid = groups_names.group_uuid
    WHERE
      groups.group_uuid = $1 :: uuid
  |]


selectUserPublicKeys :: Statement UUID (Vector (ByteString, Text))
selectUserPublicKeys =
  [vectorStatement|
    SELECT
      users_public_keys.public_key :: bytea,
      users_public_keys.description :: text
    FROM
      users_public_keys
    WHERE
      users_public_keys.user_uuid = $1 :: uuid
  |]


selectUserPolicyIds :: Statement UUID (Vector UUID)
selectUserPolicyIds =
  [vectorStatement|
    SELECT
      users_policies.policy_uuid :: uuid
    FROM
      users_policies
    WHERE
      users_policies.user_uuid = $1 :: uuid
  |]


selectUserPolicies :: Statement UUID (Vector Value)
selectUserPolicies =
  [vectorStatement|
    SELECT
      policies.policy :: jsonb
    FROM
      users_policies
    JOIN
      policies
    ON
      users_policies.policy_uuid = policies.policy_uuid
    WHERE
      users_policies.user_uuid = $1 :: uuid
  |]


selectGroupIdByName :: Statement Text (Maybe UUID)
selectGroupIdByName =
  [maybeStatement|
    SELECT
      groups_names.group_uuid :: uuid
    FROM
      groups_names
    WHERE
      groups_names.group_name = $1 :: text
  |]


deleteUserUUID :: Statement UUID ()
deleteUserUUID =
  [resultlessStatement|
    DELETE FROM
      users
    WHERE
      users.user_uuid = $1 :: uuid
  |]


deleteUserEmail :: Statement UUID ()
deleteUserEmail =
  [resultlessStatement|
    DELETE FROM
      users_emails
    WHERE
      users_emails.user_uuid = $1 :: uuid
  |]


deleteUserGroups :: Statement UUID ()
deleteUserGroups =
  [resultlessStatement|
    DELETE FROM
      users_groups
    WHERE
      users_groups.user_uuid = $1 :: uuid
  |]


deleteUserPolicies :: Statement UUID ()
deleteUserPolicies =
  [resultlessStatement|
    DELETE FROM
      users_policies
    WHERE
      users_policies.user_uuid = $1 :: uuid
  |]


deleteUserPublicKeys :: Statement UUID ()
deleteUserPublicKeys =
  [resultlessStatement|
    DELETE FROM
      users_public_keys
    WHERE
      users_public_keys.user_uuid = $1 :: uuid
  |]
