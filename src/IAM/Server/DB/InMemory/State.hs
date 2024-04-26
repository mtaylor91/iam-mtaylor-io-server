{-# LANGUAGE RankNTypes #-}
module IAM.Server.DB.InMemory.State
  ( module IAM.Server.DB.InMemory.State
  ) where

import Data.Maybe
import Data.Text

import IAM.Group
import IAM.GroupIdentifier
import IAM.Login
import IAM.Policy
import IAM.User
import IAM.UserPublicKey
import IAM.UserIdentifier
import IAM.Session


data InMemoryState = InMemoryState
  { users :: ![UserId]
  , groups :: ![GroupId]
  , logins :: ![LoginResponse SessionId]
  , policies :: ![Policy]
  , sessions :: ![(Text, Session)]
  , usersNames :: ![(UserId, Text)]
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
  , logins = []
  , policies = []
  , sessions = []
  , usersNames = []
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
lookupUserIdentifier s uid =
  let mName = lookup uid $ usersNames s
      mEmail = lookup uid $ usersEmails s
   in UserIdentifier (Just uid) mName mEmail


lookupPolicyIdentifier :: InMemoryState -> PolicyId -> PolicyIdentifier
lookupPolicyIdentifier s pid =
  case Prelude.filter ((== pid) . policyId) $ policies s of
    [] -> PolicyId pid
    policy:_ ->
      case policyName policy of
        Just name -> PolicyIdAndName pid name
        Nothing -> PolicyId pid


lookupUser :: InMemoryState -> UserId -> User
lookupUser s uid =
  let gs = [lookupGroupIdentifier s gid |
            (uid', gid) <- memberships s, uid' == uid]
      ps = [lookupPolicyIdentifier s pid |
            (uid', pid) <- userPolicyAttachments s, uid' == uid]
      pks = [pk | (uid', pk) <- usersPublicKeys s, uid' == uid]
      maybeName = lookup uid $ usersNames s
      maybeEmail = lookup uid $ usersEmails s
   in User uid maybeName maybeEmail gs ps pks


lookupGroup :: InMemoryState -> GroupId -> Maybe Text -> Group
lookupGroup s gid maybeName =
  let ps = [lookupPolicyIdentifier s pid |
            (gid', pid) <- groupPolicyAttachments s, gid' == gid]
      us = [lookupUserIdentifier s uid |
            (uid, gid') <- memberships s, gid' == gid]
   in Group gid maybeName us ps


loginState :: forall f. Functor f =>
  LoginRequestId ->
    (Maybe (LoginResponse SessionId) -> f (Maybe (LoginResponse SessionId))) ->
      InMemoryState -> f InMemoryState
loginState lid f s =
  case Prelude.filter ((== lid) . loginResponseRequest) $ logins s of
    [] -> l <$> f Nothing
    login:_ -> l <$> f (Just login)
  where l = updateLoginState s lid


userIdState :: forall f. Functor f =>
  UserId -> (Maybe User -> f (Maybe User)) -> InMemoryState -> f InMemoryState
userIdState uid f s =
  case Prelude.filter (== uid) $ users s of
    [] -> u <$> f Nothing
    _:_ -> u <$> f (Just $ lookupUser s uid)
  where u = updateUserState s uid


userIdentifierState :: forall f. Functor f =>
  UserIdentifier -> (Maybe User -> f (Maybe User)) -> InMemoryState -> f InMemoryState
userIdentifierState (UserIdentifier (Just uid) _ _) f s =
  case Prelude.filter (== uid) $ users s of
    [] -> u <$> f Nothing
    _:_ -> u <$> f (Just $ lookupUser s uid)
  where u = updateUserState s uid
userIdentifierState (UserIdentifier Nothing (Just name) mEmail) f s =
  case Prelude.filter ((== name) . snd) $ usersNames s of
    [] -> s <$ f Nothing
    (uid, _):_ -> userIdentifierState (UserIdentifier (Just uid) mEmail Nothing) f s
userIdentifierState (UserIdentifier Nothing Nothing (Just email)) f s =
  case Prelude.filter ((== email) . snd) $ usersEmails s of
    [] -> s <$ f Nothing
    (uid, _):_ -> userIdentifierState (UserIdentifier (Just uid) Nothing Nothing) f s
userIdentifierState (UserIdentifier Nothing Nothing Nothing) f s = s <$ f Nothing


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


updateLoginState ::
  InMemoryState -> LoginRequestId -> Maybe (LoginResponse SessionId) -> InMemoryState
updateLoginState s lid Nothing = s
  { logins = Prelude.filter ((/= lid) . loginResponseRequest) (logins s) }
updateLoginState s lid (Just login) = s
  { logins = login : Prelude.filter ((/= lid) . loginResponseRequest) (logins s) }


updateUserState :: InMemoryState -> UserId -> Maybe User -> InMemoryState
updateUserState s uid Nothing = s
  { users = Prelude.filter (/= uid) (users s)
  , usersEmails = Prelude.filter ((/= uid) . fst) (usersEmails s)
  , memberships = Prelude.filter ((/= uid) . fst) (memberships s)
  , userPolicyAttachments = Prelude.filter ((/= uid) . fst) (userPolicyAttachments s)
  , usersPublicKeys = Prelude.filter ((/= uid) . fst) (usersPublicKeys s)
  }
updateUserState s uid (Just (User _ maybeName maybeEmail gs ps pks)) = s
  { users = uid : Prelude.filter (/= uid) (users s)
  , usersNames = updateUsersNames maybeName
  , usersEmails = updateUsersEmails maybeEmail
  , memberships = Prelude.foldr
    (\gid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveGroupIdentifier s) gs)
  , userPolicyAttachments = Prelude.foldr
    (\pid -> (:) (uid, pid) . Prelude.filter (/= (uid, pid)))
    (userPolicyAttachments s) (mapMaybe (resolvePolicyIdentifier s) ps)
  , usersPublicKeys = Prelude.foldr
    (\pk -> (:) (uid, pk) . Prelude.filter (/= (uid, pk))) (usersPublicKeys s) pks
  }
  where
    updateUsersNames Nothing =
      Prelude.filter ((/= uid) . fst) (usersNames s)
    updateUsersNames (Just name) =
      (uid, name) : Prelude.filter ((/= uid) . fst) (usersNames s)
    updateUsersEmails Nothing =
      Prelude.filter ((/= uid) . fst) (usersEmails s)
    updateUsersEmails (Just email) =
      (uid, email) : Prelude.filter ((/= uid) . fst) (usersEmails s)


updateGroupState :: InMemoryState -> GroupId -> Maybe Group -> InMemoryState
updateGroupState s gid (Just (Group _ Nothing us ps)) = s
  { groups = gid : Prelude.filter (/= gid) (groups s)
  , memberships = Prelude.foldr
    (\uid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveUserIdentifier s) us)
  , groupPolicyAttachments = Prelude.foldr
    (\pid -> (:) (gid, pid) . Prelude.filter (/= (gid, pid)))
    (groupPolicyAttachments s) (mapMaybe (resolvePolicyIdentifier s) ps)
  }
updateGroupState s gid (Just (Group _ (Just name) us ps)) = s
  { groups = gid : Prelude.filter (/= gid) (groups s)
  , groupsNames = (gid, name) : Prelude.filter ((/= gid) . fst) (groupsNames s)
  , memberships = Prelude.foldr
    (\uid -> (:) (uid, gid) . Prelude.filter (/= (uid, gid)))
    (memberships s) (mapMaybe (resolveUserIdentifier s) us)
  , groupPolicyAttachments = Prelude.foldr
    (\pid -> (:) (gid, pid) . Prelude.filter (/= (gid, pid)))
    (groupPolicyAttachments s) (mapMaybe (resolvePolicyIdentifier s) ps)
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
resolveUserIdentifier s (UserIdentifier (Just uid) _ _) =
  case Prelude.filter (== uid) $ users s of
    [] -> Nothing
    _: _ -> Just uid
resolveUserIdentifier s (UserIdentifier _ (Just name) _) =
  case Prelude.filter ((== name) . snd) $ usersNames s of
    [] -> Nothing
    (uid, _):_ -> Just uid
resolveUserIdentifier s (UserIdentifier _ _ (Just email)) =
  case Prelude.filter ((== email) . snd) $ usersEmails s of
    [] -> Nothing
    (uid, _):_ -> Just uid
resolveUserIdentifier _ (UserIdentifier Nothing Nothing Nothing) = Nothing


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


resolvePolicyIdentifier :: InMemoryState -> PolicyIdentifier -> Maybe PolicyId
resolvePolicyIdentifier s (PolicyIdAndName pid _) =
  resolvePolicyIdentifier s (PolicyId pid)
resolvePolicyIdentifier s (PolicyName name) =
  case Prelude.filter ((== Just name) . policyName) $ policies s of
    [] -> Nothing
    policy:_ -> Just $ policyId policy
resolvePolicyIdentifier s (PolicyId pid) =
  case Prelude.filter ((== pid) . policyId) $ policies s of
    [] -> Nothing
    _: _ -> Just pid
