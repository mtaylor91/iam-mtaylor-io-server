{-# LANGUAGE QuasiQuotes #-}
module IAM.Server.DB.Postgres.Queries
  ( module IAM.Server.DB.Postgres.Queries
  ) where

import Data.Aeson (Value)
import Data.ByteString (ByteString)
import Data.Int (Int32)
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import Data.Vector (Vector)
import Hasql.Statement (Statement)
import Hasql.TH (maybeStatement, resultlessStatement, singletonStatement, vectorStatement)
import Network.IP.Addr (NetAddr, IP)


insertUserId :: Statement UUID ()
insertUserId =
  [resultlessStatement|
    INSERT INTO
      users (user_uuid)
    VALUES
      ($1 :: uuid)
  |]


insertUserName :: Statement (UUID, Text) ()
insertUserName =
  [resultlessStatement|
    INSERT INTO
      users_names (user_uuid, user_name)
    VALUES
      ($1 :: uuid, $2 :: text)
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


insertPolicy :: Statement (UUID, Text, Value) ()
insertPolicy =
  [resultlessStatement|
    INSERT INTO
      policies (policy_uuid, policy_host, policy)
    VALUES
      ($1 :: uuid, $2 :: text, $3 :: jsonb)
    RETURNING
      policy_uuid :: uuid
  |]


insertPolicyName :: Statement (UUID, Text) ()
insertPolicyName =
  [resultlessStatement|
    INSERT INTO
      policies_names (policy_uuid, policy_name)
    VALUES
      ($1 :: uuid, $2 :: text)
  |]


insertMembership :: Statement (UUID, UUID) ()
insertMembership =
  [resultlessStatement|
    INSERT INTO
      users_groups (user_uuid, group_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertUserPolicyAttachment :: Statement (UUID, UUID) ()
insertUserPolicyAttachment =
  [resultlessStatement|
    INSERT INTO
      users_policies (user_uuid, policy_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertGroupPolicyAttachment :: Statement (UUID, UUID) ()
insertGroupPolicyAttachment =
  [resultlessStatement|
    INSERT INTO
      groups_policies (group_uuid, policy_uuid)
    VALUES
      ($1 :: uuid, $2 :: uuid)
  |]


insertSession :: Statement (UUID, UUID, NetAddr IP, Text, UTCTime) ()
insertSession =
  [resultlessStatement|
    INSERT INTO
      sessions (session_uuid, user_uuid, session_addr, session_token, session_expires)
    VALUES
      ($1 :: uuid, $2 :: uuid, $3 :: inet, $4 :: text, $5 :: timestamptz)
  |]


selectUserCount :: Statement () Int32
selectUserCount =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      users
  |]


selectUserCountLike :: Statement Text Int32
selectUserCountLike =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      users
    LEFT JOIN
      users_names
    ON
      users.user_uuid = users_names.user_uuid
    LEFT JOIN
      users_emails
    ON
      users.user_uuid = users_emails.user_uuid
    WHERE
      users.user_uuid :: text LIKE $1 :: text
    OR
      users_names.user_name LIKE $1 :: text
    OR
      users_emails.user_email LIKE $1 :: text
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


selectUserIdByName :: Statement Text (Maybe UUID)
selectUserIdByName =
  [maybeStatement|
    SELECT
      users_names.user_uuid :: uuid
    FROM
      users_names
    WHERE
      users_names.user_name = $1 :: text
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


selectUserIdentifiers :: Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiers =
  [vectorStatement|
    SELECT
      users.user_uuid :: uuid,
      users_names.user_name :: text?,
      users_emails.user_email :: text?
    FROM
      users
    LEFT JOIN
      users_names
    ON
      users.user_uuid = users_names.user_uuid
    LEFT JOIN
      users_emails
    ON
      users.user_uuid = users_emails.user_uuid
    ORDER BY
      users_emails.user_email,
      users.user_uuid
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersLike ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLike =
  [vectorStatement|
    SELECT
      users.user_uuid :: uuid,
      users_names.user_name :: text?,
      users_emails.user_email :: text?
    FROM
      users
    LEFT JOIN
      users_names
    ON
      users.user_uuid = users_names.user_uuid
    LEFT JOIN
      users_emails
    ON
      users.user_uuid = users_emails.user_uuid
    WHERE
      users_emails.user_email LIKE $1 :: text
    OR
      users_names.user_name LIKE $1 :: text
    OR
      users.user_uuid :: text LIKE $1 :: text
    ORDER BY
      users_emails.user_email,
      users.user_uuid
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectUserName :: Statement UUID (Maybe Text)
selectUserName =
  [maybeStatement|
    SELECT
      users_names.user_name :: text
    FROM
      users_names
    WHERE
      users_names.user_uuid = $1 :: uuid
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
    INNER JOIN
      users_groups
    ON
      groups.group_uuid = users_groups.group_uuid
    LEFT JOIN
      groups_names
    ON
      groups.group_uuid = groups_names.group_uuid
    WHERE
      users_groups.user_uuid = $1 :: uuid
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


selectUserPolicyIdentifiers :: Statement UUID (Vector (UUID, Maybe Text))
selectUserPolicyIdentifiers =
  [vectorStatement|
    SELECT
      users_policies.policy_uuid :: uuid,
      policies_names.policy_name :: text?
    FROM
      users_policies
    LEFT JOIN
      policies_names
    ON
      users_policies.policy_uuid = policies_names.policy_uuid
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


selectUserPoliciesForHost :: Statement (UUID, Text) (Vector Value)
selectUserPoliciesForHost =
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
    AND
      policies.policy_host = $2 :: text
  |]


selectGroupCount :: Statement () Int32
selectGroupCount =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      groups
  |]


selectGroupCountLike :: Statement Text Int32
selectGroupCountLike =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      groups
    LEFT JOIN
      groups_names
    ON
      groups.group_uuid = groups_names.group_uuid
    WHERE
      groups.group_uuid :: text LIKE $1 :: text
    OR
      groups_names.group_name LIKE $1 :: text
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


selectGroupIdentifiers :: Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiers =
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
    ORDER BY
      groups_names.group_name,
      groups.group_uuid
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectGroupIdentifiersLike :: Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersLike =
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
      groups.group_uuid :: text LIKE $1 :: text
    OR
      groups_names.group_name LIKE $1 :: text
    ORDER BY
      groups_names.group_name,
      groups.group_uuid
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
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


selectGroupUsers :: Statement UUID (Vector (UUID, Maybe Text, Maybe Text))
selectGroupUsers =
  [vectorStatement|
    SELECT
      users_groups.user_uuid :: uuid,
      users_names.user_name :: text?,
      users_emails.user_email :: text?
    FROM
      users_groups
    LEFT JOIN
      users_names
    ON
      users_groups.user_uuid = users_names.user_uuid
    LEFT JOIN
      users_emails
    ON
      users_groups.user_uuid = users_emails.user_uuid
    WHERE
      users_groups.group_uuid = $1 :: uuid
  |]


selectGroupPolicyIdentifiers :: Statement UUID (Vector (UUID, Maybe Text))
selectGroupPolicyIdentifiers =
  [vectorStatement|
    SELECT
      groups_policies.policy_uuid :: uuid,
      policies_names.policy_name :: text?
    FROM
      groups_policies
    LEFT JOIN
      policies_names
    ON
      groups_policies.policy_uuid = policies_names.policy_uuid
    WHERE
      groups_policies.group_uuid = $1 :: uuid
  |]


selectGroupPoliciesForHost :: Statement (UUID, Text) (Vector Value)
selectGroupPoliciesForHost =
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
    AND
      policies.policy_host = $2 :: text
  |]


selectPolicyCount :: Statement () Int32
selectPolicyCount =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      policies
  |]


selectPolicyCountLike :: Statement Text Int32
selectPolicyCountLike =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      policies
    LEFT JOIN
      policies_names
    ON
      policies.policy_uuid = policies_names.policy_uuid
    WHERE
      policies.policy_uuid :: text LIKE $1 :: text
    OR
      policies_names.policy_name LIKE $1 :: text
  |]


selectPolicyIds :: Statement (Int32, Int32) (Vector UUID)
selectPolicyIds =
  [vectorStatement|
    SELECT
      policies.policy_uuid :: uuid
    FROM
      policies
    ORDER BY
      policies.policy_uuid
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectPolicyIdentifiers :: Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiers =
  [vectorStatement|
    SELECT
      policies.policy_uuid :: uuid,
      policies_names.policy_name :: text?
    FROM
      policies
    LEFT JOIN
      policies_names
    ON
      policies.policy_uuid = policies_names.policy_uuid
    ORDER BY
      policies_names.policy_name,
      policies.policy_uuid
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectPolicyIdentifiersLike :: Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersLike =
  [vectorStatement|
    SELECT
      policies.policy_uuid :: uuid,
      policies_names.policy_name :: text?
    FROM
      policies
    LEFT JOIN
      policies_names
    ON
      policies.policy_uuid = policies_names.policy_uuid
    WHERE
      policies.policy_uuid :: text LIKE $1 :: text
    OR
      policies_names.policy_name LIKE $1 :: text
    ORDER BY
      policies_names.policy_name,
      policies.policy_uuid
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectPolicyIdByName :: Statement Text (Maybe UUID)
selectPolicyIdByName =
  [maybeStatement|
    SELECT
      policies_names.policy_uuid :: uuid
    FROM
      policies_names
    WHERE
      policies_names.policy_name = $1 :: text
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


selectSessionById :: Statement (UUID, UUID) (Maybe (NetAddr IP, UTCTime))
selectSessionById =
  [maybeStatement|
    SELECT
      sessions.session_addr :: inet,
      sessions.session_expires :: timestamptz
    FROM
      sessions
    WHERE
      sessions.user_uuid = $1 :: uuid
    AND
      sessions.session_uuid = $2 :: uuid
  |]


selectSessionByToken :: Statement (UUID, Text) (Maybe (UUID, NetAddr IP, UTCTime))
selectSessionByToken =
  [maybeStatement|
    SELECT
      sessions.user_uuid :: uuid,
      sessions.session_addr :: inet,
      sessions.session_expires :: timestamptz
    FROM
      sessions
    WHERE
      sessions.user_uuid = $1 :: uuid
    AND
      sessions.session_token = $2 :: text
  |]


selectUserSessionCount :: Statement UUID Int32
selectUserSessionCount =
  [singletonStatement|
    SELECT
      COUNT(*) :: int
    FROM
      sessions
    WHERE
      sessions.user_uuid = $1 :: uuid
  |]


selectUserSessions ::
  Statement (UUID, Int32, Int32) (Vector (UUID, NetAddr IP, UTCTime))
selectUserSessions =
  [vectorStatement|
    SELECT
      sessions.session_uuid :: uuid,
      sessions.session_addr :: inet,
      sessions.session_expires :: timestamptz
    FROM
      sessions
    WHERE
      sessions.user_uuid = $1 :: uuid
    ORDER BY
      sessions.session_expires
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
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


updateSessionExpiration :: Statement (UUID, UTCTime) ()
updateSessionExpiration =
  [resultlessStatement|
    UPDATE
      sessions
    SET
      session_expires = $2 :: timestamptz
    WHERE
      session_uuid = $1 :: uuid
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


deleteUserPolicyAttachment :: Statement (UUID, UUID) ()
deleteUserPolicyAttachment =
  [resultlessStatement|
    DELETE FROM
      users_policies
    WHERE
      user_uuid = $1 :: uuid
    AND
      policy_uuid = $2 :: uuid
  |]


deleteGroupPolicyAttachment :: Statement (UUID, UUID) ()
deleteGroupPolicyAttachment =
  [resultlessStatement|
    DELETE FROM
      groups_policies
    WHERE
      group_uuid = $1 :: uuid
    AND
      policy_uuid = $2 :: uuid
  |]


deleteSession :: Statement UUID ()
deleteSession =
  [resultlessStatement|
    DELETE FROM
      sessions
    WHERE
      session_uuid = $1 :: uuid
  |]


replaceSession :: Statement (UUID, UUID, Text, UTCTime) ()
replaceSession =
  [resultlessStatement|
    UPDATE
      sessions
    SET
      user_uuid = $2 :: uuid,
      session_token = $3 :: text,
      session_expires = $4 :: timestamptz
    WHERE
      session_uuid = $1 :: uuid
  |]
