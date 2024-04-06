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


insertUserId :: Statement UUID ()
insertUserId =
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


insertGroupId :: Statement UUID ()
insertGroupId =
  [resultlessStatement|
    INSERT INTO
      groups (group_uuid)
    VALUES
      ($1 :: uuid)
  |]


insertGroupName :: Statement (UUID, Text) ()
insertGroupName =
  [resultlessStatement|
    INSERT INTO
      groups_names (group_uuid, group_name)
    VALUES
      ($1 :: uuid, $2 :: text)
  |]


insertGroupUser :: Statement (UUID, UUID) ()
insertGroupUser =
  [resultlessStatement|
    INSERT INTO
      users_groups (user_uuid, group_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertGroupPolicy :: Statement (UUID, UUID) ()
insertGroupPolicy =
  [resultlessStatement|
    INSERT INTO
      groups_policies (group_uuid, policy_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertPolicy :: Statement (UUID, Value) ()
insertPolicy =
  [resultlessStatement|
    INSERT INTO
      policies (policy_uuid, policy)
    VALUES
      ($1 :: uuid, $2 :: jsonb)
    RETURNING
      policy_uuid :: uuid
  |]


insertMembership :: Statement (UUID, UUID) ()
insertMembership =
  [resultlessStatement|
    INSERT INTO
      users_groups (user_uuid, group_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


selectUserId :: Statement UUID (Maybe UUID)
selectUserId =
  [maybeStatement|
    SELECT
      users.user_uuid :: uuid
    FROM
      users
    WHERE
      users.user_uuid = $1 :: uuid
  |]


selectUserIdByEmail :: Statement Text (Maybe UUID)
selectUserIdByEmail =
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


selectUserEmail :: Statement UUID (Maybe Text)
selectUserEmail =
  [maybeStatement|
    SELECT
      users_emails.user_email :: text
    FROM
      users_emails
    WHERE
      users_emails.user_uuid = $1 :: uuid
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


selectGroupId :: Statement UUID (Maybe UUID)
selectGroupId =
  [maybeStatement|
    SELECT
      groups.group_uuid :: uuid
    FROM
      groups
    WHERE
      groups.group_uuid = $1 :: uuid
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


selectGroupIds :: Statement () (Vector UUID)
selectGroupIds =
  [vectorStatement|
    SELECT
      groups.group_uuid :: uuid
    FROM
      groups
  |]


selectGroupName :: Statement UUID (Maybe Text)
selectGroupName =
  [maybeStatement|
    SELECT
      groups_names.group_name :: text
    FROM
      groups_names
    WHERE
      groups_names.group_uuid = $1 :: uuid
  |]


selectGroupUsers :: Statement UUID (Vector (UUID, Maybe Text))
selectGroupUsers =
  [vectorStatement|
    SELECT
      users_groups.user_uuid :: uuid,
      users_emails.user_email :: text?
    FROM
      users_groups
    LEFT JOIN
      users_emails
    ON
      users_groups.user_uuid = users_emails.user_uuid
    WHERE
      users_groups.group_uuid = $1 :: uuid
  |]


selectGroupPolicyIds :: Statement UUID (Vector UUID)
selectGroupPolicyIds =
  [vectorStatement|
    SELECT
      groups_policies.policy_uuid :: uuid
    FROM
      groups_policies
    WHERE
      groups_policies.group_uuid = $1 :: uuid
  |]


selectGroupPolicies :: Statement UUID (Vector Value)
selectGroupPolicies =
  [vectorStatement|
    SELECT
      policies.policy :: jsonb
    FROM
      groups_policies
    JOIN
      policies
    ON
      groups_policies.policy_uuid = policies.policy_uuid
    WHERE
      groups_policies.group_uuid = $1 :: uuid
  |]


selectPolicyIds :: Statement () (Vector UUID)
selectPolicyIds =
  [vectorStatement|
    SELECT
      policies.policy_uuid :: uuid
    FROM
      policies
  |]


selectPolicy :: Statement UUID (Maybe Value)
selectPolicy =
  [maybeStatement|
    SELECT
      policies.policy :: jsonb
    FROM
      policies
    WHERE
      policies.policy_uuid = $1 :: uuid
  |]


updatePolicy :: Statement (UUID, Value) ()
updatePolicy =
  [resultlessStatement|
    UPDATE
      policies
    SET
      policy = $2 :: jsonb
    WHERE
      policy_uuid = $1 :: uuid
  |]


deleteUserId :: Statement UUID ()
deleteUserId =
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


deleteGroupId :: Statement UUID ()
deleteGroupId =
  [resultlessStatement|
    DELETE FROM
      groups
    WHERE
      groups.group_uuid = $1 :: uuid
  |]


deleteGroupName :: Statement UUID ()
deleteGroupName =
  [resultlessStatement|
    DELETE FROM
      groups_names
    WHERE
      groups_names.group_uuid = $1 :: uuid
  |]


deleteGroupUsers :: Statement UUID ()
deleteGroupUsers =
  [resultlessStatement|
    DELETE FROM
      users_groups
    WHERE
      users_groups.group_uuid = $1 :: uuid
  |]


deleteGroupPolicies :: Statement UUID ()
deleteGroupPolicies =
  [resultlessStatement|
    DELETE FROM
      groups_policies
    WHERE
      groups_policies.group_uuid = $1 :: uuid
  |]


deletePolicy :: Statement UUID ()
deletePolicy =
  [resultlessStatement|
    DELETE FROM
      policies
    WHERE
      policies.policy_uuid = $1 :: uuid
  |]


deleteMembership :: Statement (UUID, UUID) ()
deleteMembership =
  [resultlessStatement|
    DELETE FROM
      users_groups
    WHERE
      user_uuid = $1 :: uuid
    AND
      group_uuid = $2 :: uuid
  |]
