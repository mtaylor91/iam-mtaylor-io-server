{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
module IAM.Server.DB.Postgres.Queries
  ( module IAM.Server.DB.Postgres.Queries
  ) where

import Crypto.Sign.Ed25519 (PublicKey)
import Data.Aeson (Value)
import Data.ByteString (ByteString)
import Data.Functor.Contravariant ((>$<))
import Data.Int (Int32)
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import Data.Vector (Vector)
import Hasql.Statement (Statement(..))
import Hasql.TH (maybeStatement, resultlessStatement, singletonStatement, vectorStatement)
import Network.IP.Addr (NetAddr, IP)
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E

import IAM.Ip
import IAM.Login
import IAM.Session
import IAM.Server.DB.Postgres.Encoders
import IAM.Server.DB.Postgres.Decoders
import IAM.UserIdentifier
import IAM.UserPublicKey


insertLoginRequest :: Statement (LoginResponse SessionId) ()
insertLoginRequest =
  Statement sql loginResponseEncoder D.noResult True
  where
    sql = "INSERT INTO logins \
          \(login_uuid, user_uuid, public_key, description, session_uuid,\
          \ login_addr, login_expires, login_granted, login_denied) \
          \VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"


insertUserId :: Statement UUID ()
insertUserId =
  [resultlessStatement|
    INSERT INTO
      users (user_uuid)
    VALUES
      ($1 :: uuid)
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


selectLoginRequest ::
  Statement (UserId, LoginRequestId) (Maybe (LoginResponse SessionId))
selectLoginRequest =
  Statement sql loginIdentityEncoder (D.rowMaybe loginResponseDecoder) True
  where
    sql = "SELECT \
          \logins.login_uuid, \
          \logins.user_uuid, \
          \logins.public_key, \
          \logins.description, \
          \logins.session_uuid, \
          \logins.login_addr, \
          \logins.login_expires, \
          \logins.login_granted, \
          \logins.login_denied \
          \FROM logins \
          \WHERE logins.user_uuid = $1 AND logins.login_uuid = $2"


selectLoginRequestsByUserId ::
  Statement (UserId, (Int32, Int32)) [LoginResponse SessionId]
selectLoginRequestsByUserId =
  Statement sql userIdRangeEncoder (D.rowList loginResponseDecoder) True
  where
    sql = "SELECT \
          \logins.login_uuid, \
          \logins.user_uuid, \
          \logins.public_key, \
          \logins.description, \
          \logins.session_uuid, \
          \logins.login_addr, \
          \logins.login_expires, \
          \logins.login_granted, \
          \logins.login_denied \
          \FROM logins \
          \WHERE logins.user_uuid = $1 \
          \ORDER BY logins.login_uuid ASC \
          \OFFSET $2 LIMIT $3"


selectLoginRequestsByUserIdCount :: Statement UserId Int32
selectLoginRequestsByUserIdCount =
  Statement sql userIdEncoder (D.singleRow (D.column (D.nonNullable D.int4))) True
  where
    sql = "SELECT COUNT(*) FROM logins WHERE logins.user_uuid = $1"


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


selectUserIdentifiersOrderByIdAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersOrderByIdAsc =
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
      users.user_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersOrderByIdDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersOrderByIdDesc =
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
      users.user_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersOrderByNameAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersOrderByNameAsc =
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
      users_names.user_name ASC,
      users.user_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersOrderByNameDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersOrderByNameDesc =
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
      users_names.user_name DESC,
      users.user_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersOrderByEmailAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersOrderByEmailAsc =
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
      users_emails.user_email ASC,
      users.user_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersOrderByEmailDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersOrderByEmailDesc =
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
      users_emails.user_email DESC,
      users.user_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectUserIdentifiersLikeOrderByIdAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLikeOrderByIdAsc =
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
      users.user_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectUserIdentifiersLikeOrderByIdDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLikeOrderByIdDesc =
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
      users.user_uuid DESC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectUserIdentifiersLikeOrderByNameAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLikeOrderByNameAsc =
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
      users_names.user_name ASC,
      users.user_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectUserIdentifiersLikeOrderByNameDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLikeOrderByNameDesc =
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
      users_names.user_name DESC,
      users.user_uuid DESC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectUserIdentifiersLikeOrderByEmailAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLikeOrderByEmailAsc =
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
      users_emails.user_email ASC,
      users.user_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectUserIdentifiersLikeOrderByEmailDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text, Maybe Text))
selectUserIdentifiersLikeOrderByEmailDesc =
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
      users_emails.user_email DESC,
      users.user_uuid DESC
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


selectUserGroup :: Statement (UUID, UUID) (Maybe UUID)
selectUserGroup =
  [maybeStatement|
    SELECT
      users_groups.group_uuid :: uuid
    FROM
      users_groups
    WHERE
      users_groups.user_uuid = $1 :: uuid
    AND
      users_groups.group_uuid = $2 :: uuid
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


selectUserPublicKey :: Statement (UserId, PublicKey) (Maybe UserPublicKey)
selectUserPublicKey =
  Statement sql userPublicKeyIdentityEncoder (D.rowMaybe userPublicKeyDecoder) True
  where
    sql = "SELECT \
          \users_public_keys.public_key, \
          \users_public_keys.description \
          \FROM users_public_keys \
          \WHERE users_public_keys.user_uuid = $1 AND users_public_keys.public_key = $2"


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


selectUserPublicKeysCount :: Statement UserId Int32
selectUserPublicKeysCount =
  Statement sql userIdEncoder (D.singleRow (D.column (D.nonNullable D.int4))) True
  where
    sql = "SELECT COUNT(*) FROM users_public_keys WHERE users_public_keys.user_uuid = $1"


selectUserPublicKeysRange :: Statement (UserId, (Int32, Int32)) [UserPublicKey]
selectUserPublicKeysRange =
  Statement sql userIdRangeEncoder (D.rowList userPublicKeyDecoder) True
  where
    sql = "SELECT \
          \users_public_keys.public_key, \
          \users_public_keys.description \
          \FROM users_public_keys \
          \WHERE users_public_keys.user_uuid = $1 \
          \ORDER BY users_public_keys.public_key ASC \
          \OFFSET $2 LIMIT $3"


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


selectGroupIdentifiersOrderByIdAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersOrderByIdAsc =
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
      groups.group_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectGroupIdentifiersOrderByIdDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersOrderByIdDesc =
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
      groups.group_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectGroupIdentifiersOrderByNameAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersOrderByNameAsc =
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
      groups_names.group_name ASC,
      groups.group_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectGroupIdentifiersOrderByNameDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersOrderByNameDesc =
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
      groups_names.group_name DESC,
      groups.group_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectGroupIdentifiersLikeOrderByIdAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersLikeOrderByIdAsc =
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
      groups.group_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectGroupIdentifiersLikeOrderByIdDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersLikeOrderByIdDesc =
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
      groups.group_uuid DESC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectGroupIdentifiersLikeOrderByNameAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersLikeOrderByNameAsc =
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
      groups_names.group_name ASC,
      groups.group_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectGroupIdentifiersLikeOrderByNameDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectGroupIdentifiersLikeOrderByNameDesc =
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
      groups_names.group_name DESC,
      groups.group_uuid DESC
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


selectPolicyIdentifiersOrderByIdAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersOrderByIdAsc =
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
      policies.policy_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectPolicyIdentifiersOrderByIdDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersOrderByIdDesc =
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
      policies.policy_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectPolicyIdentifiersOrderByNameAsc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersOrderByNameAsc =
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
      policies_names.policy_name ASC,
      policies.policy_uuid ASC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectPolicyIdentifiersOrderByNameDesc ::
  Statement (Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersOrderByNameDesc =
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
      policies_names.policy_name DESC,
      policies.policy_uuid DESC
    OFFSET
      $1 :: int
    LIMIT
      $2 :: int
  |]


selectPolicyIdentifiersLikeOrderByIdAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersLikeOrderByIdAsc =
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
      policies.policy_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectPolicyIdentifiersLikeOrderByIdDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersLikeOrderByIdDesc =
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
      policies.policy_uuid DESC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectPolicyIdentifiersLikeOrderByNameAsc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersLikeOrderByNameAsc =
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
      policies_names.policy_name ASC,
      policies.policy_uuid ASC
    OFFSET
      $2 :: int
    LIMIT
      $3 :: int
  |]


selectPolicyIdentifiersLikeOrderByNameDesc ::
  Statement (Text, Int32, Int32) (Vector (UUID, Maybe Text))
selectPolicyIdentifiersLikeOrderByNameDesc =
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
      policies_names.policy_name DESC,
      policies.policy_uuid DESC
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


selectSessionById :: Statement UUID (Maybe (UUID, NetAddr IP, UTCTime))
selectSessionById =
  [maybeStatement|
    SELECT
      sessions.user_uuid :: uuid,
      sessions.session_addr :: inet,
      sessions.session_expires :: timestamptz
    FROM
      sessions
    WHERE
      sessions.session_uuid = $1 :: uuid
  |]


selectUserSessionById :: Statement (UUID, UUID) (Maybe (NetAddr IP, UTCTime))
selectUserSessionById =
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


selectSessionCount :: Statement () Int32
selectSessionCount = Statement sql encoder decoder True where
  sql = "SELECT COUNT(*) FROM sessions"
  encoder = E.noParams
  decoder = D.singleRow (D.column (D.nonNullable D.int4))


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


selectSessions :: Statement (Int32, Int32) [Session]
selectSessions = Statement sql encoder decoder True where
  sql = "SELECT \
        \sessions.session_uuid, \
        \sessions.user_uuid, \
        \sessions.session_addr, \
        \sessions.session_expires \
        \FROM sessions \
        \ORDER BY sessions.session_expires ASC \
        \OFFSET $1 LIMIT $2"
  encoder = (fst >$< E.param (E.nonNullable E.int4)) <>
            (snd >$< E.param (E.nonNullable E.int4))
  decoder = D.rowList
    ( Session <$> (SessionUUID <$> D.column (D.nonNullable D.uuid))
              <*> (IpAddr <$> D.column (D.nonNullable D.inet))
              <*> (UserUUID <$> D.column (D.nonNullable D.uuid))
              <*> D.column (D.nonNullable D.timestamptz) )


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


upsertUserName :: Statement (UserId, Text) ()
upsertUserName =
  Statement sql userIdTextEncoder D.noResult True
  where
    sql = "INSERT INTO users_names (user_uuid, user_name) VALUES ($1, $2) \
          \ON CONFLICT (user_uuid) DO UPDATE SET user_name = $2"


upsertUserEmail :: Statement (UserId, Text) ()
upsertUserEmail =
  Statement sql userIdTextEncoder D.noResult True
  where
    sql = "INSERT INTO users_emails (user_uuid, user_email) VALUES ($1, $2) \
          \ON CONFLICT (user_uuid) DO UPDATE SET user_email = $2"


upsertLoginRequest :: Statement (LoginResponse SessionId) ()
upsertLoginRequest = Statement sql loginResponseEncoder D.noResult True where
  sql = "INSERT INTO logins \
        \(login_uuid, user_uuid, public_key, description, session_uuid,\
        \ login_addr, login_expires, login_granted, login_denied) \
        \VALUES \
        \($1, $2, $3, $4, $5, $6, $7, $8, $9) \
        \ON CONFLICT (login_uuid) DO UPDATE \
        \SET \
        \user_uuid = $2, \
        \public_key = $3, \
        \description = $4, \
        \session_uuid = $5, \
        \login_addr = $6, \
        \login_expires = $7, \
        \login_granted = $8, \
        \login_denied = $9"


upsertUserPublicKey :: Statement (UserId, UserPublicKey) ()
upsertUserPublicKey = Statement sql userIdUserPublicKeyEncoder D.noResult True where
  sql = "INSERT INTO users_public_keys \
        \(user_uuid, public_key, description) \
        \VALUES \
        \($1, $2, $3) \
        \ON CONFLICT (user_uuid, public_key) DO UPDATE \
        \SET \
        \description = $3"


deleteLoginRequest :: Statement (UserId, LoginRequestId) ()
deleteLoginRequest = Statement sql loginIdentityEncoder D.noResult True where
  sql = "DELETE FROM logins WHERE user_uuid = $1 AND login_uuid = $2"


deleteUserId :: Statement UserId ()
deleteUserId = Statement sql userIdEncoder D.noResult True where
  sql = "DELETE FROM users WHERE user_uuid = $1"


deleteUserEmail :: Statement UserId ()
deleteUserEmail = Statement sql userIdEncoder D.noResult True where
  sql = "DELETE FROM users_emails WHERE user_uuid = $1"


deleteUserName :: Statement UserId ()
deleteUserName = Statement sql userIdEncoder D.noResult True where
  sql = "DELETE FROM users_names WHERE user_uuid = $1"


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


deleteUserPublicKey :: Statement (UserId, PublicKey) ()
deleteUserPublicKey =
  Statement sql userPublicKeyIdentityEncoder D.noResult True
  where
    sql = "DELETE FROM users_public_keys WHERE user_uuid = $1 AND public_key = $2"


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
