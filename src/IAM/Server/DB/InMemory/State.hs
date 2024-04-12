{-# LANGUAGE RankNTypes #-}
module IAM.Server.DB.InMemory.State
  ( module IAM.Server.DB.InMemory.State
  ) where

import Data.Maybe
import Data.Text

import IAM.Group
import IAM.Identifiers
import IAM.Policy
import IAM.User
import IAM.Session


data InMemoryState = InMemoryState
  { users :: ![UserId]
  , groups :: ![GroupId]
  , policies :: ![Policy]
  , sessions :: ![(Text, Session)]
  , usersEmails :: ![(UserId, Text)]
  , groupsNames :: ![(GroupId, Text)]
  , memberships :: ![(UserId, GroupId)]
  , userPolicyAttachments :: ![(UserId, PolicyId)]
  , groupPolicyAttachments :: ![(GroupId, PolicyId)]
  , usersPublicKeys :: ![(UserId, UserPublicKey)]
  } deriving (Show)


newInMemoryState :: InMemoryState
newInMemoryState = InMemoryState
  { users = []
  , groups = []
  , policies = []
  , sessions = []
  , usersEmails = []
  , groupsNames = []
  , memberships = []
  , userPolicyAttachments = []
  , groupPolicyAttachments = []
  , usersPublicKeys = []
  }


lookupGroupIdentifier :: InMemoryState -> GroupId -> GroupIdentifier
lookupGroupIdentifier s gid = case lookup gid $ groupsNames s of
  Just name -> GroupIdAndName gid name
  Nothing -> GroupId gid


lookupUserIdentifier :: InMemoryState -> UserId -> UserIdentifier
lookupUserIdentifier s uid = case lookup uid $ usersEmails s of
  Just email -> UserIdAndEmail uid email
  Nothing -> UserId uid


lookupUser :: InMemoryState -> UserId -> Maybe Text -> User
lookupUser s uid maybeEmail =
  let gs = [lookupGroupIdentifier s gid | (uid', gid) <- memberships s, uid' == uid]
      ps = [pid | (uid', pid) <- userPolicyAttachments s, uid' == uid]
      pks = [pk | (uid', pk) <- usersPublicKeys s, uid' == uid]
   in User uid maybeEmail gs ps pks


lookupGroup :: InMemoryState -> GroupId -> Maybe Text -> Group
lookupGroup s gid maybeName =
  let ps = [pid | (gid', pid) <- groupPolicyAttachments s, gid' == gid]
      us = [lookupUserIdentifier s uid | (uid, gid') <- memberships s, gid' == gid]
   in Group gid maybeName us ps


userState :: forall f. Functor f =>
  UserIdentifier -> (Maybe User -> f (Maybe User)) -> InMemoryState -> f InMemoryState
userState (UserIdAndEmail uid _) f s = userState (UserId uid) f s
userState (UserEmail email) f s =
  case Prelude.filter ((== email) . snd) $ usersEmails s of
    [] -> s <$ f Nothing
    (uid, _):_ -> userState (UserId uid) f s
userState (UserId uid) f s =
  case Prelude.filter (== uid) $ users s of
    [] -> u <$> f Nothing
    _:_ -> u <$> f (Just $ lookupUser s uid (lookup uid $ usersEmails s))
  where u = updateUserState s uid


groupState :: forall f. Functor f =>
  GroupIdentifier -> (Maybe Group -> f (Maybe Group)) -> InMemoryState -> f InMemoryState
groupState (GroupIdAndName gid _) f s = groupState (GroupId gid) f s
groupState (GroupName name) f s =
  case Prelude.filter ((== name) . snd) $ groupsNames s of
    [] -> s <$ f Nothing
    (gid, _):_ -> groupState (GroupId gid) f s
groupState (GroupId gid) f s =
  case Prelude.filter (== gid) $ groups s of
    [] -> g <$> f Nothing
    _:_ -> g <$> f (Just $ lookupGroup s gid (lookup gid $ groupsNames s))
  where g = updateGroupState s gid


policyState :: forall f. Functor f =>
  PolicyId -> (Maybe Policy -> f (Maybe Policy)) -> InMemoryState -> f InMemoryState
policyState pid f s =
  case Prelude.filter ((== pid) . policyId) $ policies s of
    [] -> p <$> f Nothing
    policy:_ -> p <$> f (Just policy)
  where p = updatePolicyState s pid


sessionStateById :: forall f. Functor f =>
  SessionId -> (Maybe Session -> f (Maybe Session)) -> InMemoryState -> f InMemoryState
sessionStateById sid f s =
  case Prelude.filter ((== sid) . sessionId . snd) $ sessions s of
    [] -> g <$> f Nothing
    (_, session):_ -> g <$> f (Just session)
  where g = updateSessionStateById s sid


sessionStateByToken :: forall f. Functor f =>
  Text -> (Maybe Session -> f (Maybe Session)) -> InMemoryState -> f InMemoryState
sessionStateByToken token f s =
  case Prelude.filter ((== token) . fst) $ sessions s of
    [] -> g <$> f Nothing
    (_, session):_ -> g <$> f (Just session)
  where g = updateSessionStateByToken s token


updateUserState :: InMemoryState -> UserId -> Maybe User -> InMemoryState
updateUserState s uid (Just (User _ Nothing gs ps pks)) = s
  { users = uid : Prelude.filter (/= uid) (users s)
  , memberships = Prelude.foldr
    (\gid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveGroupIdentifier s) gs)
  , userPolicyAttachments = Prelude.foldr
    (\(uid', pid) -> (:) (uid', pid) . Prelude.filter (/= (uid', pid)))
    (userPolicyAttachments s) [(uid, pid) | pid <- ps]
  , usersPublicKeys = Prelude.foldr
    (\pk -> (:) (uid, pk) . Prelude.filter (/= (uid, pk))) (usersPublicKeys s) pks
  }
updateUserState s uid (Just (User _ (Just email) gs ps pks)) = s
  { users = uid : Prelude.filter (/= uid) (users s)
  , usersEmails = (uid, email) : Prelude.filter ((/= uid) . fst) (usersEmails s)
  , memberships = Prelude.foldr
    (\gid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveGroupIdentifier s) gs)
  , userPolicyAttachments = Prelude.foldr
    (\(uid', pid) -> (:) (uid', pid) . Prelude.filter (/= (uid', pid)))
    (userPolicyAttachments s) [(uid, pid) | pid <- ps]
  , usersPublicKeys = Prelude.foldr
    (\pk -> (:) (uid, pk) . Prelude.filter (/= (uid, pk))) (usersPublicKeys s) pks
  }
updateUserState s uid Nothing = s
  { users = Prelude.filter (/= uid) (users s)
  , usersEmails = Prelude.filter ((/= uid) . fst) (usersEmails s)
  , memberships = Prelude.filter ((/= uid) . fst) (memberships s)
  , userPolicyAttachments = Prelude.filter ((/= uid) . fst) (userPolicyAttachments s)
  , usersPublicKeys = Prelude.filter ((/= uid) . fst) (usersPublicKeys s)
  }


updateGroupState :: InMemoryState -> GroupId -> Maybe Group -> InMemoryState
updateGroupState s gid (Just (Group _ Nothing us ps)) = s
  { groups = gid : Prelude.filter (/= gid) (groups s)
  , memberships = Prelude.foldr
    (\uid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveUserIdentifier s) us)
  , groupPolicyAttachments = Prelude.foldr
    (\(gid', pid) -> (:) (gid', pid) . Prelude.filter (/= (gid', pid)))
    (groupPolicyAttachments s) [(gid, pid) | pid <- ps]
  }
updateGroupState s gid (Just (Group _ (Just name) us ps)) = s
  { groups = gid : Prelude.filter (/= gid) (groups s)
  , groupsNames = (gid, name) : Prelude.filter ((/= gid) . fst) (groupsNames s)
  , memberships = Prelude.foldr
    (\uid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveUserIdentifier s) us)
  , groupPolicyAttachments = Prelude.foldr
    (\(gid', pid) -> (:) (gid', pid) . Prelude.filter (/= (gid', pid)))
    (groupPolicyAttachments s) [(gid, pid) | pid <- ps]
  }
updateGroupState s gid Nothing = s
  { groups = Prelude.filter (/= gid) (groups s)
  , groupsNames = Prelude.filter ((/= gid) . fst) (groupsNames s)
  , memberships = Prelude.filter ((/= gid) . snd) (memberships s)
  , groupPolicyAttachments = Prelude.filter ((/= gid) . fst) (groupPolicyAttachments s)
  }


updatePolicyState :: InMemoryState -> PolicyId -> Maybe Policy -> InMemoryState
updatePolicyState s pid (Just p) = s
  { policies = p : Prelude.filter ((/= pid) . policyId) (policies s) }
updatePolicyState s pid Nothing = s
  { policies = Prelude.filter ((/= pid) . policyId) (policies s) }


updateSessionStateById :: InMemoryState -> SessionId -> Maybe Session -> InMemoryState
updateSessionStateById s sid (Just session) = s
  { sessions = fmap f (sessions s) }
    where f (token, s') = if sessionId s' == sid then (token, session) else (token, s')
updateSessionStateById s sid Nothing = s
  { sessions = Prelude.filter ((/= sid) . sessionId . snd) (sessions s) }


updateSessionStateByToken :: InMemoryState -> Text -> Maybe Session -> InMemoryState
updateSessionStateByToken s token (Just session) = s
  { sessions = (token, session) : Prelude.filter ((/= token) . fst) (sessions s) }
updateSessionStateByToken s token Nothing
  = s { sessions = Prelude.filter ((/= token) . fst) (sessions s) }


resolveUserIdentifier :: InMemoryState -> UserIdentifier -> Maybe UserId
resolveUserIdentifier s (UserIdAndEmail uid _) = resolveUserIdentifier s (UserId uid)
resolveUserIdentifier s (UserEmail email) =
  case Prelude.filter ((== email) . snd) $ usersEmails s of
    [] -> Nothing
    (uid, _):_ -> Just uid
resolveUserIdentifier s (UserId uid) =
  case Prelude.filter (== uid) $ users s of
    [] -> Nothing
    _: _ -> Just uid


resolveGroupIdentifier :: InMemoryState -> GroupIdentifier -> Maybe GroupId
resolveGroupIdentifier s (GroupIdAndName gid _) = resolveGroupIdentifier s (GroupId gid)
resolveGroupIdentifier s (GroupName name) =
  case Prelude.filter ((== name) . snd) $ groupsNames s of
    [] -> Nothing
    (gid, _):_ -> Just gid
resolveGroupIdentifier s (GroupId gid) =
  case Prelude.filter (== gid) $ groups s of
    [] -> Nothing
    _: _ -> Just gid
