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
import IAM.Server.DB.Postgres.Transactions


newtype PostgresDB = PostgresDB Pool

connectToDatabase :: (MonadIO m) =>
  ByteString -> Word16 -> ByteString -> ByteString -> ByteString -> m PostgresDB
connectToDatabase host port database username password = do
  let settings = Connection.settings host port username password database
  pool <- liftIO $ Pool.acquire 3 1800 1800 settings
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

  getUser (PostgresDB pool) uid =
    runTransaction pool $ pgGetUser uid

  getUserId (PostgresDB pool) uid =
    runTransaction pool $ pgGetUserId uid

  listUsers (PostgresDB pool) range =
    runTransaction pool $ pgListUsers range

  createUser (PostgresDB pool) u =
    runTransaction pool $ pgCreateUser u

  deleteUser (PostgresDB pool) uid =
    runTransaction pool $ pgDeleteUser uid

  getGroup (PostgresDB pool) gid =
    runTransaction pool $ pgGetGroup gid

  listGroups (PostgresDB pool) range =
    runTransaction pool $ pgListGroups range
    
  createGroup (PostgresDB pool) g =
    runTransaction pool $ pgCreateGroup g

  deleteGroup (PostgresDB pool) gid =
    runTransaction pool $ pgDeleteGroup gid

  getPolicy (PostgresDB pool) pid =
    runTransaction pool $ pgGetPolicy pid

  listPolicyIds (PostgresDB pool) range =
    runTransaction pool $ pgListPolicies range

  listPoliciesForUser (PostgresDB pool) uid host =
    runTransaction pool $ pgListPoliciesForUser host uid

  createPolicy (PostgresDB pool) p =
    runTransaction pool $ pgCreatePolicy p

  updatePolicy (PostgresDB pool) p =
    runTransaction pool $ pgUpdatePolicy p

  deletePolicy (PostgresDB pool) pid =
    runTransaction pool $ pgDeletePolicy pid

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

  createSession (PostgresDB pool) s =
    runTransaction pool $ pgCreateSession s

  getSession (PostgresDB pool) uid sid =
    runTransaction pool $ pgGetSession uid sid

  deleteSession (PostgresDB pool) uid sid =
    runTransaction pool $ pgDeleteSession uid sid

  replaceSession (PostgresDB pool) uid s =
    runTransaction pool $ pgReplaceSession uid s

  listUserSessions (PostgresDB pool) uid range =
    runTransaction pool $ pgListUserSessions uid range
