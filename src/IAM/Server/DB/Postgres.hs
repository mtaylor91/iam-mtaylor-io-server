{-# LANGUAGE FlexibleContexts #-}
module IAM.Server.DB.Postgres ( connectToDatabase, PostgresDB(..) ) where

import Control.Monad.Except
import Data.ByteString (ByteString)
import Data.Word (Word16)
import Hasql.Pool (Pool)
import Hasql.Transaction (Transaction)
import Hasql.Transaction.Sessions
import qualified Hasql.Connection as Connection
import qualified Hasql.Pool as Pool

import IAM.Server.DB
import IAM.Server.DB.Postgres.Transactions


newtype PostgresDB = PostgresDB Pool

connectToDatabase :: (MonadIO m) =>
  ByteString -> Word16 -> ByteString -> ByteString -> ByteString -> m PostgresDB
connectToDatabase host port database username password = do
  let settings = Connection.settings host port username password database
  pool <- liftIO $ Pool.acquire 3 1800 1800 settings
  return $ PostgresDB pool


runTransaction :: (MonadIO m, MonadError DBError m) =>
  Pool -> Transaction (Either DBError a) -> m a
runTransaction pool t = do
  result0 <- liftIO $ do
    result1 <- Pool.use pool $ transaction ReadCommitted Write t
    case result1 of
      Right (Right a) -> return $ Right a
      Right (Left err) -> return $ Left err
      Left err -> print err >> return (Left InternalError)
  either throwError return result0



instance DB PostgresDB where

  getUser (PostgresDB pool) uid =
    runTransaction pool $ pgGetUser uid

  listUsers (PostgresDB pool) range =
    runTransaction pool $ pgListUsers range

  createUser (PostgresDB pool) u =
    runTransaction pool $ pgCreateUser u

  deleteUser (PostgresDB pool) uid =
    runTransaction pool $ pgDeleteUser uid

  getGroup (PostgresDB pool) gid =
    runTransaction pool $ pgGetGroup gid

  listGroups (PostgresDB pool) =
    runTransaction pool pgListGroups
    
  createGroup (PostgresDB pool) g =
    runTransaction pool $ pgCreateGroup g

  deleteGroup (PostgresDB pool) gid =
    runTransaction pool $ pgDeleteGroup gid

  getPolicy (PostgresDB pool) pid =
    runTransaction pool $ pgGetPolicy pid

  listPolicies (PostgresDB pool) =
    runTransaction pool pgListPolicies

  listPoliciesForUser (PostgresDB pool) uid =
    runTransaction pool $ pgListPoliciesForUser uid

  createPolicy (PostgresDB pool) p =
    runTransaction pool $ pgCreatePolicy p

  updatePolicy (PostgresDB pool) p =
    runTransaction pool $ pgUpdatePolicy p

  deletePolicy (PostgresDB pool) pid =
    runTransaction pool $ pgDeletePolicy pid

  createMembership (PostgresDB pool) uid gid =
    runTransaction pool $ pgCreateMembership uid gid
