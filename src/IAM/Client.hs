{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module IAM.Client
  ( getCaller
  , deleteCaller
  , mkCallerPolicyClient
  , mkCallerSessionsClient
  , listUsers
  , createUser
  , mkUserClient
  , listGroups
  , createGroup
  , mkGroupClient
  , listPolicies
  , createPolicy
  , mkPolicyClient
  , createMembership
  , deleteMembership
  , authorizeClient
  , UserClient(..)
  , UserPolicyClient(..)
  , UserSessionsClient(..)
  , UserSessionClient(..)
  , GroupClient(..)
  , GroupPolicyClient(..)
  , PolicyClient(..)
  ) where

import Servant
import Servant.Client
import Data.UUID (UUID)
import IAM.API

import IAM.Authorization
import IAM.Group
import IAM.GroupPolicy
import IAM.Identifiers
import IAM.Membership
import IAM.Policy
import IAM.Session
import IAM.User
import IAM.UserPolicy


type UsersClientM
  = (Maybe Int -> Maybe Int -> ClientM [UserIdentifier])
  :<|> (User -> ClientM User)
  :<|> (UserIdentifier -> UserClientM)


type UserClientM =
    ClientM User
    :<|> ClientM User
    :<|> (UUID -> UserPolicyClientM)
    :<|> UserSessionsClientM


type UserPolicyClientM
  = ClientM UserPolicyAttachment
  :<|> ClientM UserPolicyAttachment


type UserSessionsClientM
  = ClientM Session
  :<|> (Maybe Int -> Maybe Int -> ClientM [Session])
  :<|> (SessionId -> UserSessionClientM)


type UserSessionClientM
  = ClientM Session
  :<|> ClientM Session
  :<|> ClientM Session


type GroupsClientM
  = (Maybe Int -> Maybe Int -> ClientM [GroupIdentifier])
  :<|> (Group -> ClientM Group)
  :<|> (GroupIdentifier -> GroupClientM)


type GroupClientM =
    ClientM Group
    :<|> ClientM Group
    :<|> (UUID -> GroupPolicyClientM)
    :<|> (UserIdentifier -> GroupMembershipClientM)


type GroupPolicyClientM =
  ClientM GroupPolicyAttachment :<|> ClientM GroupPolicyAttachment


type GroupMembershipClientM
  = ClientM Membership
  :<|> ClientM Membership


type PoliciesClientM
  = (Maybe Int -> Maybe Int -> ClientM [UUID])
  :<|> (Policy -> ClientM Policy)
  :<|> (UUID -> PolicyClientM)


type PolicyClientM =
    ClientM Policy
    :<|> ClientM Policy


type AuthorizationClientM
  = AuthorizationRequest -> ClientM AuthorizationResponse


data UserClient = UserClient
  { getUser :: !(ClientM User)
  , deleteUser :: !(ClientM User)
  , userPolicyClient :: !(UUID -> UserPolicyClient)
  , userSessionsClient :: !UserSessionsClient
  }


data UserPolicyClient = UserPolicyClient
  { attachUserPolicy :: !(ClientM UserPolicyAttachment)
  , detachUserPolicy :: !(ClientM UserPolicyAttachment)
  }


data UserSessionsClient = UserSessionsClient
  { createSession :: !(ClientM Session)
  , listSessions :: !(Maybe Int -> Maybe Int -> ClientM [Session])
  , sessionClient :: !(SessionId -> UserSessionClient)
  }


data UserSessionClient = UserSessionClient
  { getSession :: !(ClientM Session)
  , deleteSession :: !(ClientM Session)
  , refreshSession :: !(ClientM Session)
  }


data GroupClient = GroupClient
  { getGroup :: !(ClientM Group)
  , deleteGroup :: !(ClientM Group)
  , groupPolicyClient :: !(UUID -> GroupPolicyClient)
  , memberClient :: !(UserIdentifier -> MembershipClient)
  }


data GroupPolicyClient = GroupPolicyClient
  { attachGroupPolicy :: !(ClientM GroupPolicyAttachment)
  , detachGroupPolicy :: !(ClientM GroupPolicyAttachment)
  }


data MembershipClient = MembershipClient
  { createMembership :: !(ClientM Membership)
  , deleteMembership :: !(ClientM Membership)
  }


data PolicyClient = PolicyClient
  { getPolicy :: !(ClientM Policy)
  , deletePolicy :: !(ClientM Policy)
  }


callerClient :: UserClientM
usersClient :: UsersClientM
groupsClient :: GroupsClientM
policiesClient :: PoliciesClientM
authorizeClient :: AuthorizationClientM


callerClient
  :<|> usersClient
  :<|> groupsClient
  :<|> policiesClient
  :<|> authorizeClient
  = client iamAPI


getCaller :: ClientM User
deleteCaller :: ClientM User
callerPolicyClient :: UUID -> UserPolicyClientM
callerSessionClient :: UserSessionsClientM


(getCaller :<|> deleteCaller :<|> callerPolicyClient :<|> callerSessionClient) =
  callerClient


mkCallerPolicyClient :: UUID -> UserPolicyClient
mkCallerPolicyClient pid =
  let (attachUserPolicy' :<|> detachUserPolicy') = callerPolicyClient pid
  in UserPolicyClient attachUserPolicy' detachUserPolicy'


mkCallerSessionsClient :: UserSessionsClient
mkCallerSessionsClient =
  let (createSession' :<|> listSessions' :<|> sessionClient') = callerSessionClient
      sessionClient'' = mkCallerSessionsClient' sessionClient'
  in UserSessionsClient createSession' listSessions' sessionClient''
  where
  mkCallerSessionsClient' ::
    (SessionId -> UserSessionClientM) -> SessionId -> UserSessionClient
  mkCallerSessionsClient' sessionClient' sid =
    let (getSession' :<|> deleteSession' :<|> refreshSession') = sessionClient' sid
    in UserSessionClient getSession' deleteSession' refreshSession'


listUsers :: Maybe Int -> Maybe Int -> ClientM [UserIdentifier]
createUser :: User -> ClientM User
userClient :: UserIdentifier -> UserClientM


(listUsers :<|> createUser :<|> userClient) = usersClient


mkUserClient :: UserIdentifier -> UserClient
mkUserClient uid =
  let (getUser' :<|> deleteUser' :<|> userPolicyClient' :<|> userSessionClient') =
        userClient uid
      userPolicyClient'' = mkUserPolicyClient userPolicyClient'
      userSessionClient'' = mkUserSessionsClient userSessionClient'
  in UserClient getUser' deleteUser' userPolicyClient'' userSessionClient''

  where

  mkUserPolicyClient :: (UUID -> UserPolicyClientM) -> UUID -> UserPolicyClient
  mkUserPolicyClient userPolicyClient' pid =
    let (attachUserPolicy' :<|> detachUserPolicy') = userPolicyClient' pid
    in UserPolicyClient attachUserPolicy' detachUserPolicy'

  mkUserSessionsClient :: UserSessionsClientM -> UserSessionsClient
  mkUserSessionsClient userSessionClient' =
    let (createSession' :<|> listSessions' :<|> sessionClient') = userSessionClient'
        sessionClient'' = mkUserSessionClient sessionClient'
    in UserSessionsClient createSession' listSessions' sessionClient''

  mkUserSessionClient ::
    (SessionId -> UserSessionClientM) -> SessionId -> UserSessionClient
  mkUserSessionClient sessionClient' sid =
    let (getSession' :<|> deleteSession' :<|> refreshSession') = sessionClient' sid
    in UserSessionClient getSession' deleteSession' refreshSession'


listGroups :: Maybe Int -> Maybe Int -> ClientM [GroupIdentifier]
createGroup :: Group -> ClientM Group
groupClient :: GroupIdentifier -> GroupClientM


(listGroups :<|> createGroup :<|> groupClient) = groupsClient


mkGroupClient :: GroupIdentifier -> GroupClient
mkGroupClient gid =
  let (getGroup' :<|> deleteGroup' :<|> groupPolicyClient' :<|> memberClient')
        = groupClient gid
      groupPolicyClient'' = mkGroupPolicyClient groupPolicyClient'
      memberClient'' = mkMembershipClient memberClient'
  in GroupClient getGroup' deleteGroup' groupPolicyClient'' memberClient''
  where
  mkGroupPolicyClient :: (UUID -> GroupPolicyClientM) -> UUID -> GroupPolicyClient
  mkGroupPolicyClient groupPolicyClient' pid =
    let (attachGroupPolicy' :<|> detachGroupPolicy') = groupPolicyClient' pid
    in GroupPolicyClient attachGroupPolicy' detachGroupPolicy'
  mkMembershipClient ::
    (UserIdentifier -> GroupMembershipClientM) -> UserIdentifier -> MembershipClient
  mkMembershipClient memberClient' uid =
    let (createMembership' :<|> deleteMembership') = memberClient' uid
    in MembershipClient createMembership' deleteMembership'


listPolicies :: Maybe Int -> Maybe Int -> ClientM [UUID]
createPolicy :: Policy -> ClientM Policy
policyClient :: UUID -> PolicyClientM


listPolicies :<|> createPolicy :<|> policyClient = policiesClient


mkPolicyClient :: UUID -> PolicyClient
mkPolicyClient pid =
  let (getPolicy' :<|> deletePolicy') = policyClient pid
  in PolicyClient getPolicy' deletePolicy'
