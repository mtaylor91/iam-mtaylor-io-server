module Lib.InMemory ( inMemory, InMemory(..) ) where

import Control.Concurrent.STM
import Control.Monad.IO.Class
import Control.Monad.Except

import Lib.DB
import Lib.IAM

-- | InMemory is an in-memory implementation of the DB typeclass.
-- It uses an IORef to store a list of users.
newtype InMemory = InMemory (TVar (([UserId], [GroupId]), [(UserId, GroupId)]))


inMemory :: IO InMemory
inMemory = InMemory <$> newTVarIO (([], []), [])


instance DB InMemory where

  getUser (InMemory tvar) uid = do
    maybeUser <- liftIO $ atomically $ do
      ((uids, _), memberships) <- readTVar tvar
      if uid `elem` uids
        then return $ Just $ User uid $ map snd $ filter ((== uid) . fst) memberships
        else return Nothing
    maybe (throwError NotFound) return maybeUser

  listUsers (InMemory tvar) =
    liftIO $ atomically $ fst . fst <$> readTVar tvar

  createUser (InMemory tvar) uid = do
    result <- liftIO $ atomically $ do
      ((uids, _), _) <- readTVar tvar
      if uid `elem` uids
        then return $ Left AlreadyExists
        else do
          modifyTVar' tvar addUser
          return $ Right ()
    either throwError return result
    where
      addUser ((uids', gids), ms) = ((uid:uids', gids), ms)

  deleteUser (InMemory tvar) uid = do
    result <- liftIO $ atomically $ do
      ((uids, _), _) <- readTVar tvar
      if uid `elem` uids
        then do
          modifyTVar' tvar delUser
          return $ Right ()
        else return $ Left NotFound
    either throwError return result
    where
      delUser ((uids', gids), ms) =
        ((filter (/= uid) uids', gids), filter ((/= uid) . fst) ms)

  getGroup (InMemory tvar) gid = do
    maybeGroup <- liftIO $ atomically $ do
      ((_, gids), memberships) <- readTVar tvar
      if gid `elem` gids
        then return $ Just $ Group gid $ map fst $ filter ((== gid) . snd) memberships
        else return Nothing
    maybe (throwError NotFound) return maybeGroup

  listGroups (InMemory tvar) =
    liftIO $ atomically $ snd . fst <$> readTVar tvar

  createGroup (InMemory tvar) gid = do
    result <- liftIO $ atomically $ do
      ((_, gids), _) <- readTVar tvar
      if gid `elem` gids
        then return $ Left AlreadyExists
        else do
          modifyTVar' tvar addGroup
          return $ Right ()
    either throwError return result
    where
      addGroup ((uids, gids'), ms) = ((uids, gid:gids'), ms)

  deleteGroup (InMemory tvar) gid = do
    result <- liftIO $ atomically $ do
      ((_, gids), _) <- readTVar tvar
      if gid `elem` gids
        then do
          modifyTVar' tvar delGroup
          return $ Right ()
        else return $ Left NotFound
    either throwError return result
    where
      delGroup ((uids, gids'), ms) =
        ((uids, filter (/= gid) gids'), filter ((/= gid) . snd) ms)

  createMembership (InMemory tvar) uid gid = do
    result <- liftIO $ atomically $ do
      ((uids, gids), ms) <- readTVar tvar
      if uid `elem` uids && gid `elem` gids
        then if (uid, gid) `notElem` ms
          then do
            modifyTVar' tvar addMembership
            return $ Right $ Membership uid gid
          else return $ Left AlreadyExists
        else return $ Left NotFound
    either throwError return result
    where
      addMembership ((uids', gids'), ms') = ((uids', gids'), (uid, gid):ms')

  deleteMembership (InMemory tvar) uid gid = do
    result <- liftIO $ atomically $ do
      ((_, _), ms) <- readTVar tvar
      if (uid, gid) `elem` ms
        then do
          modifyTVar' tvar delMembership
          return $ Right $ Membership uid gid
        else return $ Left NotFound
    either throwError return result
    where
      delMembership ((uids', gids'), ms') =
        ((uids', gids'), filter (/= (uid, gid)) ms')
