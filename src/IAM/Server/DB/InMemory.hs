module IAM.Server.DB.InMemory ( inMemory, InMemory(..) ) where

import Control.Concurrent.STM
import Control.Lens
import Control.Monad.IO.Class
import Control.Monad.Except
import Data.List (sortBy)
import Data.Text (isInfixOf)
import Data.UUID (toText)

import IAM.Error
import IAM.Group
import IAM.GroupPolicy
import IAM.GroupIdentifier
import IAM.Identifier
import IAM.Login
import IAM.ListResponse
import IAM.Membership
import IAM.Policy
import IAM.Range
import IAM.Server.DB
import IAM.Server.DB.InMemory.State
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserIdentifier
import IAM.UserPolicy
import IAM.UserPublicKey


-- | InMemory is an in-memory implementation of the DB typeclass.
newtype InMemory = InMemory (TVar InMemoryState)


inMemory :: IO InMemory
inMemory = InMemory <$> newTVarIO newInMemoryState


instance DB InMemory where

  createLoginResponse (InMemory tvar) lr = do
    liftIO $ atomically $ do
      s <- readTVar tvar
      writeTVar tvar $ s & loginState (loginResponseRequest lr) ?~ lr
    return lr

  getLoginResponse (InMemory tvar) _ lid = do
    s <- liftIO $ readTVarIO tvar
    case s ^. loginState lid of
      Just lr -> return lr
      Nothing -> throwError $ NotFound $ LoginIdentifier lid

  listLoginResponses (InMemory tvar) uid (Range offset' maybeLimit) = do
    s <- liftIO $ readTVarIO tvar
    case resolveUserIdentifier s uid of
      Just uid' -> do
        let lrs = [lr | lr <- logins s, loginResponseUserId lr == uid']
        case maybeLimit of
          Just limit' ->
            let items' = Prelude.take limit' $ Prelude.drop offset' lrs
                total' = Prelude.length lrs
             in return $ ListResponse items' limit' offset' total'
          Nothing ->
            let items' = Prelude.drop offset' lrs
                total' = Prelude.length lrs
                limit' = total'
             in return $ ListResponse items' limit' offset' total'
      Nothing ->
        throwError $ NotFound $ UserIdentifier' uid

  updateLoginResponse (InMemory tvar) _ lid f = do
    s <- liftIO $ readTVarIO tvar
    case s ^. loginState lid of
      Just lr -> do
        let lr' = f lr
        liftIO $ atomically $ do
          s' <- readTVar tvar
          writeTVar tvar $ s' & loginState lid ?~ lr'
        return lr'
      Nothing ->
        throwError $ NotFound $ LoginIdentifier lid

  deleteLoginResponse (InMemory tvar) _ lid = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case s ^. loginState lid of
        Just lr -> do
          writeTVar tvar $ s & loginState lid .~ Nothing
          return $ Right lr
        Nothing ->
          return $ Left $ NotFound $ LoginIdentifier lid
    either throwError return result

  getUser (InMemory tvar) uid = do
    s <- liftIO $ readTVarIO tvar
    case s ^. userIdentifierState uid of
      Just u -> return u
      Nothing -> throwError $ NotFound $ UserIdentifier' uid

  getUserId (InMemory tvar) uid = do
    s <- liftIO $ readTVarIO tvar
    case resolveUserIdentifier s uid of
      Just uid' -> return uid'
      Nothing -> throwError $ NotFound $ UserIdentifier' uid

  listUsers (InMemory tvar) (Range offset' maybeLimit) sort order = do
    s <- liftIO $ readTVarIO tvar
    let users' = resolveUser s <$> users s
        users'' = sortUsers sort order users'
     in return $ case maybeLimit of
      Just limit' ->
        let items' = Prelude.take limit' $ Prelude.drop offset' users''
            total' = Prelude.length users''
         in ListResponse items' limit' offset' total'
      Nothing ->
        let items' = Prelude.drop offset' users''
            total' = Prelude.length users''
            limit' = total'
         in ListResponse items' limit' offset' total'
    where
      resolveUser :: InMemoryState -> UserId -> UserIdentifier
      resolveUser s uid = case s ^. userIdState uid of
        Nothing -> UserIdentifier (Just uid) Nothing Nothing
        Just u ->
          let mName = userName u
              mEmail = userEmail u
           in UserIdentifier (Just uid) mName mEmail

  listUsersBySearchTerm (InMemory tvar) search (Range offset' maybeLimit) sort order = do
    s <- liftIO $ readTVarIO tvar
    let users' = resolveUser s <$> users s
    let users'' = sortUsers sort order $ Prelude.filter f users'
    case maybeLimit of
      Just limit' ->
        let items' = Prelude.take limit' $ Prelude.drop offset' users''
            total' = Prelude.length users''
         in return $ ListResponse items' limit' offset' total'
      Nothing ->
        let items' = Prelude.drop offset' users''
            total' = Prelude.length users''
            limit' = total'
         in return $ ListResponse items' limit' offset' total'
    where
      f :: UserIdentifier -> Bool
      f (UserIdentifier mUid mName mEmail) =
        maybe False ((search `isInfixOf`) . toText . unUserId) mUid
        || maybe False (search `isInfixOf`) mName
        || maybe False (search `isInfixOf`) mEmail

      resolveUser :: InMemoryState -> UserId -> UserIdentifier
      resolveUser s uid = case s ^. userIdState uid of
        Nothing -> UserIdentifier (Just uid) Nothing Nothing
        Just u ->
          let mName = userName u
              mEmail = userEmail u
           in UserIdentifier (Just uid) mName mEmail

  createUser (InMemory tvar) u@(User uid _ _ _ _ _) = do
    liftIO $ atomically $ do
      s <- readTVar tvar
      writeTVar tvar $ s & userIdState uid ?~ u
    return u

  updateUser (InMemory tvar) uid upd = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case s ^. userIdentifierState uid of
        Just u -> do
          writeTVar tvar $ s & userIdentifierState uid ?~ f u upd
          return $ Right u
        Nothing ->
          return $ Left $ NotFound $ UserIdentifier' uid
    either throwError return result
    where
      f :: User -> UserUpdate -> User
      f u (UserUpdateName n) = u { userName = n }
      f u (UserUpdateEmail e) = u { userEmail = e }
      f u (UserUpdateNameEmail n e) = u { userName = n, userEmail = e }

  deleteUser (InMemory tvar) uid = do
    result <- liftIO $ atomically $ do
      s <- readTVar tvar
      case s ^. userIdentifierState uid of
        Just u -> do
          writeTVar tvar $ s & userIdentifierState uid .~ Nothing
          return $ Right u
        Nothing ->
          return $ Left $ NotFound $ UserIdentifier' uid
    either throwError return result

  upsertUserPublicKey (InMemory tvar) uid pk = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case s ^. userIdState uid of
        Just u -> do
          let pks = userPublicKeys u
          let pks' = pk : Prelude.filter (/= pk) pks
          let u' = u { userPublicKeys = pks' }
          writeTVar tvar $ s & userIdState uid ?~ u'
          return $ Right pk
        Nothing ->
          return $ Left $ NotFound $ UserIdentifier' $
            UserIdentifier (Just uid) Nothing Nothing
    either throwError return result

  listUserPublicKeys (InMemory tvar) uid (Range offset' maybeLimit) = do
    s <- liftIO $ readTVarIO tvar
    case s ^. userIdState uid of
      Just u -> do
        let pks = userPublicKeys u
        case maybeLimit of
          Just limit' ->
            let items' = Prelude.take limit' $ Prelude.drop offset' pks
                total' = Prelude.length pks
             in return $ ListResponse items' limit' offset' total'
          Nothing ->
            let items' = Prelude.drop offset' pks
                total' = Prelude.length pks
                limit' = total'
             in return $ ListResponse items' limit' offset' total'
      Nothing ->
        throwError $ NotFound $ UserIdentifier' $
          UserIdentifier (Just uid) Nothing Nothing

  getUserPublicKey (InMemory tvar) uid pk = do
    s <- liftIO $ readTVarIO tvar
    case s ^. userIdState uid of
      Just u -> do
        let pks = userPublicKeys u
        case Prelude.filter ((== pk) . userPublicKey) pks of
          [] -> throwError $ NotFound $ UserPublicKeyIdentifier uid pk
          pk':_ -> return pk'
      Nothing ->
        throwError $ NotFound $ UserIdentifier' $
          UserIdentifier (Just uid) Nothing Nothing

  deleteUserPublicKey (InMemory tvar) uid pk = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case s ^. userIdState uid of
        Just u -> do
          let pks = userPublicKeys u
          case Prelude.filter ((== pk) . userPublicKey) pks of
            [] ->
              return $ Left $ NotFound $ UserPublicKeyIdentifier uid pk
            pk':_ -> do
              let pks' = Prelude.filter ((/= pk) . userPublicKey) pks
              let u' = u { userPublicKeys = pks' }
              writeTVar tvar $ s & userIdState uid ?~ u'
              return $ Right pk'
        Nothing ->
          return $ Left $ NotFound $ UserIdentifier' $
            UserIdentifier (Just uid) Nothing Nothing
    either throwError return result

  getGroup (InMemory tvar) gid = do
    s <- liftIO $ readTVarIO tvar
    case s ^. groupState gid of
      Just g -> return g
      Nothing -> throwError $ NotFound $ GroupIdentifier gid

  listGroups (InMemory tvar) (Range offset' maybeLimit) sort order = do
    s <- liftIO $ readTVarIO tvar
    let gs = sortGroups sort order $ resolveGroup s <$> groups s
    case maybeLimit of
      Just limit' ->
        let items' = Prelude.take limit' $ Prelude.drop offset' gs
            total' = Prelude.length gs
         in return $ ListResponse items' limit' offset' total'
      Nothing ->
        let items' = Prelude.drop offset' gs
            total' = Prelude.length gs
            limit' = total'
         in return $ ListResponse items' limit' offset' total'
    where
      resolveGroup :: InMemoryState -> GroupId -> GroupIdentifier
      resolveGroup s gid = case s ^. groupState (GroupId gid) of
        Nothing -> GroupId gid
        Just g ->
          case groupName g of
            Nothing -> GroupId gid
            Just name -> GroupIdAndName gid name

  listGroupsBySearchTerm (InMemory tvar) search (Range offset' maybeLimit) sort order = do
    s <- liftIO $ readTVarIO tvar
    let gs = resolveGroup s <$> groups s
    let gs' = sortGroups sort order $ Prelude.filter f gs
    case maybeLimit of
      Just limit' ->
        let items' = Prelude.take limit' $ Prelude.drop offset' gs'
            total' = Prelude.length gs'
         in return $ ListResponse items' limit' offset' total'
      Nothing ->
        let items' = Prelude.drop offset' gs'
            total' = Prelude.length gs'
            limit' = total'
         in return $ ListResponse items' limit' offset' total'
    where
      f :: GroupIdentifier -> Bool
      f (GroupName name) = search `isInfixOf` name
      f (GroupId (GroupUUID uuid)) = search `isInfixOf` toText uuid
      f (GroupIdAndName (GroupUUID uuid) name) =
        search `isInfixOf` name || search `isInfixOf` toText uuid

      resolveGroup :: InMemoryState -> GroupId -> GroupIdentifier
      resolveGroup s gid = case s ^. groupState (GroupId gid) of
        Nothing -> GroupId gid
        Just g ->
          case groupName g of
            Nothing -> GroupId gid
            Just name -> GroupIdAndName gid name

  createGroup (InMemory tvar) g@(Group gid _ _ _) = do
    liftIO $ atomically $ do
      s <- readTVar tvar
      writeTVar tvar $ s & groupState (GroupId gid) ?~ g
    return g

  deleteGroup (InMemory tvar) gid = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case s ^. groupState gid of
        Just g -> do
          writeTVar tvar $ s & groupState gid .~ Nothing
          return $ Right g
        Nothing ->
          return $ Left $ NotFound $ GroupIdentifier gid
    either throwError return result

  getPolicy (InMemory tvar) pident = do
    s <- liftIO $ readTVarIO tvar
    case resolvePolicyIdentifier s pident of
      Nothing -> throwError $ NotFound $ PolicyIdentifier pident
      Just pid ->
        case s ^. policyState pid of
          Just p -> return p
          Nothing -> throwError $ NotFound $ PolicyIdentifier $ PolicyId pid

  listPolicyIds (InMemory tvar) (Range offset' mLimit) sort order = do
    s <- liftIO $ readTVarIO tvar
    let policyIds = lookupPolicyIdentifier s . policyId <$> policies s
    let policyIds' = sortPolicies sort order policyIds
    case mLimit of
      Just limit' ->
        let items' = Prelude.take limit' $ Prelude.drop offset' policyIds'
            total' = Prelude.length policyIds'
         in return $ ListResponse items' limit' offset' total'
      Nothing ->
        let items' = Prelude.drop offset' policyIds'
            total' = Prelude.length policyIds'
            limit' = total'
         in return $ ListResponse items' limit' offset' total'

  listPolicyIdsBySearchTerm (InMemory tvar) search (Range offset' mLimit) sort order = do
    s <- liftIO $ readTVarIO tvar
    let policyIds = lookupPolicyIdentifier s . policyId <$> policies s
    let policyIds' = sortPolicies sort order $ Prelude.filter f policyIds
    case mLimit of
      Just limit' ->
        let items' = Prelude.take limit' $ Prelude.drop offset' policyIds'
            total' = Prelude.length policyIds'
         in return $ ListResponse items' limit' offset' total'
      Nothing ->
        let items' = Prelude.drop offset' policyIds'
            total' = Prelude.length policyIds'
            limit' = total'
         in return $ ListResponse items' limit' offset' total'
    where
      f :: PolicyIdentifier -> Bool
      f (PolicyName name) = search `isInfixOf` name
      f (PolicyId (PolicyUUID pid)) = search `isInfixOf` toText pid
      f (PolicyIdAndName (PolicyUUID pid) name) =
        search `isInfixOf` toText pid || search `isInfixOf` name

  listPoliciesForUser (InMemory tvar) uid host = do
    s <- liftIO $ readTVarIO tvar
    let gs = [gid | (uid', gid) <- memberships s, uid' == uid]
    let gps = [pid | (gid, pid) <- groupPolicyAttachments s, gid `Prelude.elem` gs]
    let ups = [pid | (uid', pid) <- userPolicyAttachments s, uid' == uid]
    let pids = Prelude.foldr (:) gps ups
    return $
      [ p | p <- policies s
      , hostname p == host
      , policyId p `Prelude.elem` pids
      ]

  createPolicy (InMemory tvar) p = do
    liftIO $ atomically $ do
      s <- readTVar tvar
      writeTVar tvar $ s & policyState (policyId p) ?~ p
    return p

  updatePolicy (InMemory tvar) p = do
    liftIO $ atomically $ do
      s <- readTVar tvar
      writeTVar tvar $ s & policyState (policyId p) ?~ p
      return p

  deletePolicy (InMemory tvar) pident = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case resolvePolicyIdentifier s pident of
        Nothing ->
          return $ Left $ NotFound $ PolicyIdentifier pident
        Just pid -> do
          case s ^. policyState pid of
            Just p -> do
              writeTVar tvar $ s & policyState pid .~ Nothing
              return $ Right p
            Nothing ->
              return $ Left $ NotFound $ PolicyIdentifier $ PolicyId pid
    either throwError return result

  createMembership (InMemory tvar) uid gid = do
    result <- liftIO $ atomically $ do
      s <- readTVar tvar
      case (resolveUserIdentifier s uid, resolveGroupIdentifier s gid) of
        (Just uid', Just gid') -> do
          case Prelude.filter (== (uid', gid')) $ memberships s of
            [] -> do
              writeTVar tvar $ s { memberships = (uid', gid') : memberships s }
              return $ Right $ Membership uid' gid'
            _:_ ->
              return $ Left AlreadyExists
        (Nothing, _) ->
          return $ Left $ NotFound $ UserIdentifier' uid
        (_, Nothing) ->
          return $ Left $ NotFound $ GroupIdentifier gid
    either throwError return result

  deleteMembership (InMemory tvar) uid gid = do
    result <- liftIO $ atomically $ do
      s <- readTVar tvar
      case (resolveUserIdentifier s uid, resolveGroupIdentifier s gid) of
        (Just uid', Just gid') -> do
          case Prelude.filter (== (uid', gid')) $ memberships s of
            [] ->
              return $ Left $ NotFound $ UserGroupIdentifier uid gid
            _:_ -> do
              writeTVar tvar $ s { memberships =
                Prelude.filter (/= (uid', gid')) $ memberships s }
              return $ Right $ Membership uid' gid'
        (Nothing, _) ->
          return $ Left $ NotFound $ UserIdentifier' uid
        (_, Nothing) ->
          return $ Left $ NotFound $ GroupIdentifier gid
    either throwError return result

  createUserPolicyAttachment (InMemory tvar) uid pident = do
    result <- liftIO $ atomically $ do
      s <- readTVar tvar
      case resolveUserIdentifier s uid of
        Just uid' -> do
          case resolvePolicyIdentifier s pident of
            Just pid -> do
              case Prelude.filter (== (uid', pid)) $ userPolicyAttachments s of
                [] -> do
                  writeTVar tvar $ s
                    { userPolicyAttachments = (uid', pid) : userPolicyAttachments s }
                  return $ Right $ UserPolicyAttachment uid' pid
                _:_ ->
                  return $ Left AlreadyExists
            Nothing ->
              return $ Left $ NotFound $ PolicyIdentifier pident
        Nothing ->
          return $ Left $ NotFound $ UserIdentifier' uid
    either throwError return result

  deleteUserPolicyAttachment (InMemory tvar) uid pident = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case resolveUserIdentifier s uid of
        Just uid' -> do
          case resolvePolicyIdentifier s pident of
            Just pid' -> do
              case Prelude.filter (== (uid', pid')) $ userPolicyAttachments s of
                [] ->
                  return $ Left $ NotFound $ UserPolicyIdentifier uid pident
                _:_ -> do
                  writeTVar tvar $ s { userPolicyAttachments =
                    Prelude.filter (/= (uid', pid')) $ userPolicyAttachments s }
                  return $ Right $ UserPolicyAttachment uid' pid'
            Nothing ->
              return $ Left $ NotFound $ PolicyIdentifier pident
        Nothing ->
          return $ Left $ NotFound $ UserIdentifier' uid
    either throwError return result

  createGroupPolicyAttachment (InMemory tvar) gid pident = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case resolveGroupIdentifier s gid of
        Just gid' -> do
          case resolvePolicyIdentifier s pident of
            Just pid -> do
              case Prelude.filter (== (gid', pid)) $ groupPolicyAttachments s of
                [] -> do
                  writeTVar tvar $ s
                    { groupPolicyAttachments = (gid', pid) : groupPolicyAttachments s }
                  return $ Right $ GroupPolicyAttachment gid' pid
                _:_ ->
                  return $ Left AlreadyExists
            Nothing ->
              return $ Left $ NotFound $ PolicyIdentifier pident
        Nothing ->
          return $ Left $ NotFound $ GroupIdentifier gid
    either throwError return result

  deleteGroupPolicyAttachment (InMemory tvar) gid pident = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case resolveGroupIdentifier s gid of
        Just gid' -> do
          case resolvePolicyIdentifier s pident of
            Just pid' -> do
              case Prelude.filter (== (gid', pid')) $ groupPolicyAttachments s of
                [] ->
                  return $ Left $ NotFound $ GroupPolicyIdentifier gid pident
                _:_ -> do
                  writeTVar tvar $ s { groupPolicyAttachments =
                    Prelude.filter (/= (gid', pid')) $ groupPolicyAttachments s }
                  return $ Right $ GroupPolicyAttachment gid' pid'
            Nothing ->
              return $ Left $ NotFound $ PolicyIdentifier pident
        Nothing ->
          return $ Left $ NotFound $ GroupIdentifier gid
    either throwError return result

  createSession (InMemory tvar) addr uid = do
    s <- liftIO $ IAM.Session.createSession addr uid
    liftIO $ atomically $ do
      s' <- readTVar tvar
      let newSession = (createSessionToken s, toSession s)
      writeTVar tvar $ s' { sessions = newSession : sessions s' }
    return s

  getSessionById (InMemory tvar) uid sid = do
    s <- liftIO $ readTVarIO tvar
    let maybeUid = resolveUserIdentifier s uid
    case (s ^. sessionStateById sid, maybeUid) of
      (Just session, Just uid') -> do
        if sessionUser session == uid'
          then return session
          else throwError $ NotFound $ SessionIdentifier $ Just sid
      (Nothing, _) ->
        throwError $ NotFound $ SessionIdentifier $ Just sid
      (_, Nothing) ->
        throwError $ NotFound $ UserIdentifier' uid

  getSessionByToken (InMemory tvar) uid token = do
    s <- liftIO $ readTVarIO tvar
    let maybeUid = resolveUserIdentifier s uid
    case maybeUid of
      Nothing ->
        throwError $ NotFound $ UserIdentifier' uid
      Just uid' ->
        case s ^. sessionStateByToken token of
          Just session ->
            if sessionUser session == uid'
              then return session
              else throwError $ NotFound $ SessionIdentifier Nothing
          Nothing ->
            throwError $ NotFound $ SessionIdentifier Nothing

  refreshSession (InMemory tvar) uid s = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s' -> case s' ^. sessionStateById s of
        Just session ->
          let maybeUid = resolveUserIdentifier s' uid
           in if Just (sessionUser session) == maybeUid
            then do
              let session' = IAM.Session.refreshSession session
              writeTVar tvar $ s' & sessionStateById s ?~ session'
              return $ Right session'
            else
              return $ Left $ NotFound $ SessionIdentifier $ Just s
        Nothing ->
          return $ Left $ NotFound $ SessionIdentifier $ Just s
    either throwError return result

  deleteSession (InMemory tvar) uid sid = do
    result <- liftIO $ atomically $
      readTVar tvar >>= \s -> case s ^. sessionStateById sid of
        Just session ->
          let maybeUid = resolveUserIdentifier s uid
           in if Just (sessionUser session) == maybeUid
            then do
              writeTVar tvar $ s & sessionStateById sid .~ Nothing
              return $ Right session
            else
              return $ Left $ NotFound $ SessionIdentifier $ Just sid
        Nothing ->
          return $ Left $ NotFound $ SessionIdentifier $ Just sid
    either throwError return result

  listUserSessions (InMemory tvar) uid (Range offset' maybeLimit) = do
    s <- liftIO $ readTVarIO tvar
    let maybeUid = resolveUserIdentifier s uid
    case maybeUid of
      Nothing ->
        throwError $ NotFound $ UserIdentifier' uid
      Just uid' -> do
        let sessions' = [s' | (_, s') <- sessions s, sessionUser s' == uid']
        case maybeLimit of
          Just limit' ->
            let items' = Prelude.take limit' $ Prelude.drop offset' sessions'
                total' = Prelude.length sessions'
             in return $ ListResponse items' limit' offset' total'
          Nothing ->
            let items' = Prelude.drop offset' sessions'
                total' = Prelude.length sessions'
                limit' = total'
             in return $ ListResponse items' limit' offset' total'


sortUsers :: SortUsersBy -> SortOrder -> [UserIdentifier] -> [UserIdentifier]
sortUsers sort order = sortBy f where
  f :: UserIdentifier -> UserIdentifier -> Ordering
  f uid1 uid2 =
    case (sort, order) of
      (SortUsersById, Ascending) ->
        compare (unUserIdentifierId uid1) (unUserIdentifierId uid2)
      (SortUsersById, Descending) ->
        compare (unUserIdentifierId uid2) (unUserIdentifierId uid1)
      (SortUsersByName, Ascending) ->
        compare (unUserIdentifierName uid1) (unUserIdentifierName uid2)
      (SortUsersByName, Descending) ->
        compare (unUserIdentifierName uid2) (unUserIdentifierName uid1)
      (SortUsersByEmail, Ascending) ->
        compare (unUserIdentifierEmail uid1) (unUserIdentifierEmail uid2)
      (SortUsersByEmail, Descending) ->
        compare (unUserIdentifierEmail uid2) (unUserIdentifierEmail uid1)


sortGroups :: SortGroupsBy -> SortOrder -> [GroupIdentifier] -> [GroupIdentifier]
sortGroups sort order = sortBy f where
  f :: GroupIdentifier -> GroupIdentifier -> Ordering
  f gid1 gid2 =
    case (sort, order) of
      (SortGroupsById, Ascending) ->
        compare (unGroupIdentifierId gid1) (unGroupIdentifierId gid2)
      (SortGroupsById, Descending) ->
        compare (unGroupIdentifierId gid2) (unGroupIdentifierId gid1)
      (SortGroupsByName, Ascending) ->
        compare (unGroupIdentifierName gid1) (unGroupIdentifierName gid2)
      (SortGroupsByName, Descending) ->
        compare (unGroupIdentifierName gid2) (unGroupIdentifierName gid1)


sortPolicies :: SortPoliciesBy -> SortOrder -> [PolicyIdentifier] -> [PolicyIdentifier]
sortPolicies sort order = sortBy f where
  f :: PolicyIdentifier -> PolicyIdentifier -> Ordering
  f pid1 pid2 =
    case (sort, order) of
      (SortPoliciesById, Ascending) ->
        compare (unPolicyIdentifierId pid1) (unPolicyIdentifierId pid2)
      (SortPoliciesById, Descending) ->
        compare (unPolicyIdentifierId pid2) (unPolicyIdentifierId pid1)
      (SortPoliciesByName, Ascending) ->
        compare (unPolicyIdentifierName pid1) (unPolicyIdentifierName pid2)
      (SortPoliciesByName, Descending) ->
        compare (unPolicyIdentifierName pid2) (unPolicyIdentifierName pid1)
