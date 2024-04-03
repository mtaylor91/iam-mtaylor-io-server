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
