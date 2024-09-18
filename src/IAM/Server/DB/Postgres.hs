{-# LANGUAGE FlexibleContexts #-}
module IAM.Server.DB.Postgres ( connectToDatabase, PostgresDB(..) ) where

import Control.Monad.Except
import Data.ByteString (ByteString)
import Data.Text (pack)
import Data.Word (Word16)
import Hasql.Pool (Pool)
import Hasql.Transaction (Transaction)
import Hasql.Transaction.Sessions
import qualified Hasql.Connection as Connection
import qualified Hasql.Pool as Pool

import IAM.Error
import IAM.Server.DB
import IAM.Server.DB.Postgres.Migrations
import IAM.Server.DB.Postgres.Transactions
import IAM.Session


newtype PostgresDB = PostgresDB Pool

connectToDatabase :: (MonadIO m) =>
  ByteString -> Word16 -> ByteString -> ByteString -> ByteString -> FilePath ->
    m PostgresDB
connectToDatabase host port database username password migrations = do
  let settings = Connection.settings host port username password database
  pool <- liftIO $ Pool.acquire 3 1800 1800 settings
  liftIO $ migrate migrations pool
  return $ PostgresDB pool


runTransaction :: (MonadIO m, MonadError Error m) =>
  Pool -> Transaction (Either Error a) -> m a
runTransaction pool t = do
  result0 <- liftIO $ do
    result1 <- Pool.use pool $ transaction ReadCommitted Write t
    case result1 of
      Right (Right a) -> return $ Right a
      Right (Left err) -> return $ Left err
      Left err -> return (Left $ InternalError $ pack $ show err)
  either throwError return result0



instance DB PostgresDB where

  createLoginResponse (PostgresDB pool) lr =
    runTransaction pool $ pgCreateLoginResponse lr

  getLoginResponse (PostgresDB pool) uid lid =
    runTransaction pool $ pgGetLoginResponse uid lid

  listLoginResponses (PostgresDB pool) uid range =
    runTransaction pool $ pgListLoginResponses uid range

  updateLoginResponse (PostgresDB pool) uid lid f =
    runTransaction pool $ pgUpdateLoginResponse uid lid f

  deleteLoginResponse (PostgresDB pool) uid lid =
    runTransaction pool $ pgDeleteLoginResponse uid lid

  getUser (PostgresDB pool) uid =
    runTransaction pool $ pgGetUser uid

  getUserId (PostgresDB pool) uid =
    runTransaction pool $ pgGetUserId uid

  listUsers (PostgresDB pool) range sort order =
    runTransaction pool $ pgListUsers range sort order

  listUsersBySearchTerm (PostgresDB pool) prefix range sort order =
    runTransaction pool $ pgListUsersBySearchTerm prefix range sort order

  createUser (PostgresDB pool) u =
    runTransaction pool $ pgCreateUser u

  updateUser (PostgresDB pool) uid upd =
    runTransaction pool $ pgUpdateUser uid upd

  deleteUser (PostgresDB pool) uid =
    runTransaction pool $ pgDeleteUser uid

  upsertUserPublicKey (PostgresDB pool) uid pk =
    runTransaction pool $ pgUpsertUserPublicKey uid pk

  listUserPublicKeys (PostgresDB pool) uid range =
    runTransaction pool $ pgListUserPublicKeys uid range

  getUserPublicKey (PostgresDB pool) uid pkid =
    runTransaction pool $ pgGetUserPublicKey uid pkid

  deleteUserPublicKey (PostgresDB pool) uid pkid =
    runTransaction pool $ pgDeleteUserPublicKey uid pkid

  getGroup (PostgresDB pool) gid =
    runTransaction pool $ pgGetGroup gid

  listGroups (PostgresDB pool) range sort order =
    runTransaction pool $ pgListGroups range sort order

  listGroupsBySearchTerm (PostgresDB pool) search range sort order =
    runTransaction pool $ pgListGroupsBySearchTerm search range sort order
    
  createGroup (PostgresDB pool) g =
    runTransaction pool $ pgCreateGroup g

  deleteGroup (PostgresDB pool) gid =
    runTransaction pool $ pgDeleteGroup gid

  getPolicy (PostgresDB pool) pid =
    runTransaction pool $ pgGetPolicy pid

  listPolicyIds (PostgresDB pool) range sort order =
    runTransaction pool $ pgListPolicies range sort order

  listPolicyIdsBySearchTerm (PostgresDB pool) search range sort order =
    runTransaction pool $ pgListPoliciesBySearchTerm search range sort order

  listPoliciesForUser (PostgresDB pool) uid host =
    runTransaction pool $ pgListPoliciesForUser host uid

  createPolicy (PostgresDB pool) p =
    runTransaction pool $ pgCreatePolicy p

  updatePolicy (PostgresDB pool) p =
    runTransaction pool $ pgUpdatePolicy p

  deletePolicy (PostgresDB pool) pid =
    runTransaction pool $ pgDeletePolicy pid

  getMembership (PostgresDB pool) uid gid =
    runTransaction pool $ pgGetMembership uid gid

  createMembership (PostgresDB pool) uid gid =
    runTransaction pool $ pgCreateMembership uid gid

  deleteMembership (PostgresDB pool) uid gid =
    runTransaction pool $ pgDeleteMembership uid gid

  createUserPolicyAttachment (PostgresDB pool) uid pid =
    runTransaction pool $ pgCreateUserPolicyAttachment uid pid

  deleteUserPolicyAttachment (PostgresDB pool) uid pid =
    runTransaction pool $ pgDeleteUserPolicyAttachment uid pid

  createGroupPolicyAttachment (PostgresDB pool) gid pid =
    runTransaction pool $ pgCreateGroupPolicyAttachment gid pid

  deleteGroupPolicyAttachment (PostgresDB pool) gid pid =
    runTransaction pool $ pgDeleteGroupPolicyAttachment gid pid

  createSession (PostgresDB pool) addr uid = do
    s <- liftIO $ IAM.Session.createSession addr uid
    runTransaction pool $ pgCreateSession s

  getSessionById (PostgresDB pool) sid =
    runTransaction pool $ pgGetSessionById sid

  getSessionByToken (PostgresDB pool) uid t =
    runTransaction pool $ pgGetSessionByToken uid t

  getUserSessionById (PostgresDB pool) uid sid =
    runTransaction pool $ pgGetUserSessionById uid sid

  deleteSession (PostgresDB pool) sid =
    runTransaction pool $ pgDeleteSession sid

  deleteUserSession (PostgresDB pool) uid sid =
    runTransaction pool $ pgDeleteUserSession uid sid

  refreshSession (PostgresDB pool) uid sid =
    runTransaction pool $ pgRefreshSession uid sid

  listSessions (PostgresDB pool) range sortBy sortOrder =
    runTransaction pool $ pgListSessions range sortBy sortOrder

  listSessionsBySearchTerm (PostgresDB pool) pattern range sortBy sortOrder =
    runTransaction pool $ pgListSessionsBySearchTerm pattern range sortBy sortOrder

  listUserSessions (PostgresDB pool) uid range =
    runTransaction pool $ pgListUserSessions uid range
