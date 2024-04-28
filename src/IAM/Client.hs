{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module IAM.Client
  ( login
  , getCaller
  , deleteCaller
  , listCallerLoginRequests
  , mkCallerLoginRequestClient
  , listCallerPublicKeys
  , createCallerPublicKey
  , mkCallerPublicKeyClient
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
  , LoginRequestsClient(..)
  , LoginRequestClient(..)
  , PublicKeysClient(..)
  , PublicKeyClient(..)
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
import IAM.Login
import IAM.Membership
import IAM.Policy
import IAM.PublicKey
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserIdentifier
import IAM.UserPolicy
import IAM.UserPublicKey


type UsersClientM
  = (Maybe Text -> Maybe SortUsersBy -> Maybe SortOrder -> Maybe Int -> Maybe Int ->
      ClientM (ListResponse UserIdentifier))
  :<|> (User -> ClientM User)
  :<|> (UserIdentifier -> UserClientM)


type UserClientM =
    ClientM User
    :<|> ClientM User
    :<|> LoginRequestsClientM
    :<|> PublicKeysClientM
    :<|> (PolicyIdentifier -> UserPolicyClientM)
    :<|> UserSessionsClientM


type LoginRequestsClientM
  = (Maybe Int -> Maybe Int -> ClientM (ListResponse (LoginResponse SessionId)))
  :<|> (LoginRequestId -> LoginRequestClientM)


type LoginRequestClientM
  = ClientM (LoginResponse SessionId)
  :<|> ClientM (LoginResponse SessionId)
  :<|> ClientM (LoginResponse SessionId)
  :<|> ClientM (LoginResponse SessionId)


type PublicKeysClientM
  = (Maybe Int -> Maybe Int -> ClientM (ListResponse UserPublicKey))
  :<|> (UserPublicKey -> ClientM UserPublicKey)
  :<|> (PublicKey' -> PublicKeyClientM)


type PublicKeyClientM
  = ClientM UserPublicKey
  :<|> ClientM UserPublicKey


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
  , loginRequestsClient :: !LoginRequestsClient
  , userPublicKeysClient :: !PublicKeysClient
  , userPolicyClient :: !(PolicyIdentifier -> UserPolicyClient)
  , userSessionsClient :: !UserSessionsClient
  }


data LoginRequestsClient = LoginRequestsClient
  { listLoginRequests ::
    !(Maybe Int -> Maybe Int -> ClientM (ListResponse (LoginResponse SessionId)))
  , loginRequestClient :: !(LoginRequestId -> LoginRequestClient)
  }


data LoginRequestClient = LoginRequestClient
  { getLoginRequest :: !(ClientM (LoginResponse SessionId))
  , deleteLoginRequest :: !(ClientM (LoginResponse SessionId))
  , denyLoginRequest :: !(ClientM (LoginResponse SessionId))
  , grantLoginRequest :: !(ClientM (LoginResponse SessionId))
  }


data PublicKeysClient = PublicKeysClient
  { listPublicKeys :: !(Maybe Int -> Maybe Int -> ClientM (ListResponse UserPublicKey))
  , createUserPublicKey :: !(UserPublicKey -> ClientM UserPublicKey)
  , publicKeyClient :: !(PublicKey' -> PublicKeyClient)
  }


data PublicKeyClient = PublicKeyClient
  { getUserPublicKey :: !(ClientM UserPublicKey)
  , deleteUserPublicKey :: !(ClientM UserPublicKey)
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
login :: LoginRequest -> ClientM (LoginResponse CreateSession)


callerClient
  :<|> usersClient
  :<|> groupsClient
  :<|> policiesClient
  :<|> authorizeClient
  :<|> login
  = client iamAPI


getCaller :: ClientM User
deleteCaller :: ClientM User
callerLoginRequestsClient :: LoginRequestsClientM
callerPublicKeysClient :: PublicKeysClientM
callerPolicyClient :: PolicyIdentifier -> UserPolicyClientM
callerSessionClient :: UserSessionsClientM


( getCaller
  :<|> deleteCaller
  :<|> callerLoginRequestsClient
  :<|> callerPublicKeysClient
  :<|> callerPolicyClient
  :<|> callerSessionClient ) = callerClient


listCallerLoginRequests ::
  Maybe Int -> Maybe Int -> ClientM (ListResponse (LoginResponse SessionId))
callerLoginRequestClient :: LoginRequestId -> LoginRequestClientM


( listCallerLoginRequests :<|> callerLoginRequestClient ) = callerLoginRequestsClient


mkCallerLoginRequestClient :: LoginRequestId -> LoginRequestClient
mkCallerLoginRequestClient lid =
  let ( getLoginRequest'
        :<|> deleteLoginRequest'
        :<|> denyLoginRequest'
        :<|> grantLoginRequest') = callerLoginRequestClient lid
  in LoginRequestClient
    getLoginRequest' deleteLoginRequest' denyLoginRequest' grantLoginRequest'


listCallerPublicKeys :: Maybe Int -> Maybe Int -> ClientM (ListResponse UserPublicKey)
createCallerPublicKey :: UserPublicKey -> ClientM UserPublicKey
callerPublicKeyClient :: PublicKey' -> PublicKeyClientM


( listCallerPublicKeys
  :<|> createCallerPublicKey
  :<|> callerPublicKeyClient ) = callerPublicKeysClient


mkCallerPublicKeyClient :: PublicKey' -> PublicKeyClient
mkCallerPublicKeyClient pk =
  let (getUserPublicKey' :<|> deleteUserPublicKey') = callerPublicKeyClient pk
  in PublicKeyClient getUserPublicKey' deleteUserPublicKey'


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
  let ( getUser'
        :<|> deleteUser'
        :<|> userLoginRequestsClient'
        :<|> userPublicKeysClient'
        :<|> userPolicyClient'
        :<|> userSessionClient' ) = userClient uid
      userLoginRequestsClient'' = mkLoginRequestsClient userLoginRequestsClient'
      userPublicKeysClient'' = mkPublicKeysClient userPublicKeysClient'
      userPolicyClient'' = mkUserPolicyClient userPolicyClient'
      userSessionClient'' = mkUserSessionsClient userSessionClient'
  in UserClient
    { getUser = getUser'
    , deleteUser = deleteUser'
    , loginRequestsClient = userLoginRequestsClient''
    , userPublicKeysClient = userPublicKeysClient''
    , userPolicyClient = userPolicyClient''
    , userSessionsClient = userSessionClient''
    }
  where

  mkLoginRequestsClient :: LoginRequestsClientM -> LoginRequestsClient
  mkLoginRequestsClient c =
    let (listLoginRequests' :<|> loginRequestClient') = c
        loginRequestClient'' = mkLoginRequestClient loginRequestClient'
    in LoginRequestsClient listLoginRequests' loginRequestClient''

  mkLoginRequestClient ::
    (LoginRequestId -> LoginRequestClientM) -> LoginRequestId -> LoginRequestClient
  mkLoginRequestClient f lid =
    let ( getLoginRequest'
          :<|> deleteLoginRequest'
          :<|> denyLoginRequest'
          :<|> grantLoginRequest') = f lid
    in LoginRequestClient
      getLoginRequest' deleteLoginRequest' denyLoginRequest' grantLoginRequest'

  mkPublicKeysClient :: PublicKeysClientM -> PublicKeysClient
  mkPublicKeysClient c =
    let (listPublicKeys' :<|> createUserPublicKey' :<|> publicKeyClient') = c
        publicKeyClient'' = mkPublicKeyClient publicKeyClient'
     in PublicKeysClient listPublicKeys' createUserPublicKey' publicKeyClient''

  mkPublicKeyClient ::
    (PublicKey' -> PublicKeyClientM) -> PublicKey' -> PublicKeyClient
  mkPublicKeyClient publicKeyClient' pk =
    let (getUserPublicKey' :<|> deleteUserPublicKey') = publicKeyClient' pk
     in PublicKeyClient getUserPublicKey' deleteUserPublicKey'

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
