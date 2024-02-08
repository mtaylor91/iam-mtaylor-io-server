module Lib.InMemory ( inMemory, InMemory(..) ) where

import Control.Concurrent.STM
import Control.Monad.IO.Class

import Lib.DB
import Lib.IAM

-- | InMemory is an in-memory implementation of the DB typeclass.
-- It uses an IORef to store a list of users.
newtype InMemory = InMemory (TVar (([UserId], [GroupId]), [(UserId, GroupId)]))


inMemory :: IO InMemory
inMemory = InMemory <$> newTVarIO (([], []), [])


instance DB InMemory where

  getUser (InMemory tvar) uid = liftIO $ atomically $ do
    ((uids, _), memberships) <- readTVar tvar
    if uid `elem` uids
      then return $ Just $ User uid $ map snd $ filter ((== uid) . fst) memberships
      else return Nothing

  listUsers (InMemory tvar) =
    liftIO $ atomically $ fst . fst <$> readTVar tvar

  createUser (InMemory tvar) uid = liftIO $ atomically $ do
    ((uids, _), _) <- readTVar tvar
    if uid `elem` uids
      then return Nothing
      else do
        modifyTVar' tvar addUser
        return $ Just uid
    where
      addUser ((uids', gids), ms) = ((uid:uids', gids), ms)

  deleteUser (InMemory tvar) uid = liftIO $ atomically $ do
    ((uids, _), _) <- readTVar tvar
    if uid `elem` uids
      then do
        modifyTVar' tvar delUser
        return $ Just uid
      else return Nothing
    where
      delUser ((uids', gids), ms) =
        ((filter (/= uid) uids', gids), filter ((/= uid) . fst) ms)

  getGroup (InMemory tvar) gid = liftIO $ atomically $ do
    ((_, gids), memberships) <- readTVar tvar
    if gid `elem` gids
      then return $ Just $ Group gid $ map fst $ filter ((== gid) . snd) memberships
      else return Nothing

  listGroups (InMemory tvar) =
    liftIO $ atomically $ snd . fst <$> readTVar tvar

  createGroup (InMemory tvar) gid = liftIO $ atomically $ do
    ((_, gids), _) <- readTVar tvar
    if gid `elem` gids
      then return Nothing
      else do
        modifyTVar' tvar addGroup
        return $ Just gid
    where
      addGroup ((uids, gids'), ms) = ((uids, gid:gids'), ms)

  deleteGroup (InMemory tvar) gid = liftIO $ atomically $ do
    ((_, gids), _) <- readTVar tvar
    if gid `elem` gids
      then do
        modifyTVar' tvar delGroup
        return $ Just gid
      else return Nothing
    where
      delGroup ((uids, gids'), ms) =
        ((uids, filter (/= gid) gids'), filter ((/= gid) . snd) ms)

  createMembership (InMemory tvar) uid gid = liftIO $ atomically $ do
    ((uids, gids), ms) <- readTVar tvar
    if uid `elem` uids && gid `elem` gids && (uid, gid) `notElem` ms
      then do
        modifyTVar' tvar addMembership
        return $ Just (uid, gid)
      else return Nothing
    where
      addMembership ((uids', gids'), ms') = ((uids', gids'), (uid, gid):ms')

  deleteMembership (InMemory tvar) uid gid = liftIO $ atomically $ do
    ((_, _), ms) <- readTVar tvar
    if (uid, gid) `elem` ms
      then do
        modifyTVar' tvar delMembership
        return $ Just (uid, gid)
      else return Nothing
    where
      delMembership ((uids', gids'), ms') =
        ((uids', gids'), filter (/= (uid, gid)) ms')
