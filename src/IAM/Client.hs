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

import Data.Text
import Servant
import Servant.Client
import IAM.API

import IAM.Authorization
import IAM.Group
import IAM.GroupPolicy
import IAM.GroupIdentifier
import IAM.ListResponse
import IAM.Membership
import IAM.Policy
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserPolicy
import IAM.UserIdentifier


type UsersClientM
  = (Maybe Text -> Maybe SortUsersBy -> Maybe SortOrder -> Maybe Int -> Maybe Int ->
      ClientM (ListResponse UserIdentifier))
  :<|> (User -> ClientM User)
  :<|> (UserIdentifier -> UserClientM)


type UserClientM =
    ClientM User
    :<|> ClientM User
    :<|> (PolicyIdentifier -> UserPolicyClientM)
    :<|> UserSessionsClientM


type UserPolicyClientM
  = ClientM UserPolicyAttachment
  :<|> ClientM UserPolicyAttachment


type UserSessionsClientM
  = ClientM CreateSession
  :<|> (Maybe Int -> Maybe Int -> ClientM (ListResponse Session))
  :<|> (SessionId -> UserSessionClientM)


type UserSessionClientM
  = ClientM Session
  :<|> ClientM Session
  :<|> ClientM Session


type GroupsClientM
  = (Maybe Text -> Maybe SortGroupsBy -> Maybe SortOrder -> Maybe Int -> Maybe Int ->
      ClientM (ListResponse GroupIdentifier))
  :<|> (Group -> ClientM Group)
  :<|> (GroupIdentifier -> GroupClientM)


type GroupClientM =
    ClientM Group
    :<|> ClientM Group
    :<|> (PolicyIdentifier -> GroupPolicyClientM)
    :<|> (UserIdentifier -> GroupMembershipClientM)


type GroupPolicyClientM =
  ClientM GroupPolicyAttachment :<|> ClientM GroupPolicyAttachment


type GroupMembershipClientM
  = ClientM Membership
  :<|> ClientM Membership


type PoliciesClientM
  = (Maybe Text -> Maybe SortPoliciesBy -> Maybe SortOrder -> Maybe Int -> Maybe Int ->
      ClientM (ListResponse PolicyIdentifier))
  :<|> (Policy -> ClientM Policy)
  :<|> (PolicyIdentifier -> PolicyClientM)


type PolicyClientM =
    ClientM Policy
    :<|> ClientM Policy


type AuthorizationClientM
  = AuthorizationRequest -> ClientM AuthorizationResponse


data UserClient = UserClient
  { getUser :: !(ClientM User)
  , deleteUser :: !(ClientM User)
  , userPolicyClient :: !(PolicyIdentifier -> UserPolicyClient)
  , userSessionsClient :: !UserSessionsClient
  }


data UserPolicyClient = UserPolicyClient
  { attachUserPolicy :: !(ClientM UserPolicyAttachment)
  , detachUserPolicy :: !(ClientM UserPolicyAttachment)
  }


data UserSessionsClient = UserSessionsClient
  { createSession :: !(ClientM CreateSession)
  , listSessions :: !(Maybe Int -> Maybe Int -> ClientM (ListResponse Session))
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
  , groupPolicyClient :: !(PolicyIdentifier -> GroupPolicyClient)
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
callerPolicyClient :: PolicyIdentifier -> UserPolicyClientM
callerSessionClient :: UserSessionsClientM


(getCaller :<|> deleteCaller :<|> callerPolicyClient :<|> callerSessionClient) =
  callerClient


mkCallerPolicyClient :: PolicyIdentifier -> UserPolicyClient
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


listUsers :: Maybe Text -> Maybe SortUsersBy -> Maybe SortOrder -> Maybe Int ->
  Maybe Int -> ClientM (ListResponse UserIdentifier)
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

  mkUserPolicyClient ::
    (PolicyIdentifier -> UserPolicyClientM) -> PolicyIdentifier -> UserPolicyClient
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


listGroups ::
  Maybe Text ->  Maybe SortGroupsBy -> Maybe SortOrder ->Maybe Int -> Maybe Int ->
  ClientM (ListResponse GroupIdentifier)
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
  mkGroupPolicyClient ::
    (PolicyIdentifier -> GroupPolicyClientM) -> PolicyIdentifier -> GroupPolicyClient
  mkGroupPolicyClient groupPolicyClient' pid =
    let (attachGroupPolicy' :<|> detachGroupPolicy') = groupPolicyClient' pid
    in GroupPolicyClient attachGroupPolicy' detachGroupPolicy'
  mkMembershipClient ::
    (UserIdentifier -> GroupMembershipClientM) -> UserIdentifier -> MembershipClient
  mkMembershipClient memberClient' uid =
    let (createMembership' :<|> deleteMembership') = memberClient' uid
    in MembershipClient createMembership' deleteMembership'


listPolicies ::
  Maybe Text -> Maybe SortPoliciesBy -> Maybe SortOrder ->Maybe Int -> Maybe Int ->
    ClientM (ListResponse PolicyIdentifier)
createPolicy :: Policy -> ClientM Policy
policyClient :: PolicyIdentifier -> PolicyClientM


listPolicies :<|> createPolicy :<|> policyClient = policiesClient


mkPolicyClient :: PolicyIdentifier -> PolicyClient
mkPolicyClient pid =
  let (getPolicy' :<|> deletePolicy') = policyClient pid
  in PolicyClient getPolicy' deletePolicy'
