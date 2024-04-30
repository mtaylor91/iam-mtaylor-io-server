module IAM.Server.API
  ( server
  , UserAPI
  , GroupAPI
  , UsersAPI
  , GroupsAPI
  , PolicyAPI
  , PoliciesAPI
  , UserPolicyAPI
  , GroupPolicyAPI
  ) where

import Servant

import IAM.API
import IAM.GroupIdentifier
import IAM.Login
import IAM.Policy
import IAM.PublicKey
import IAM.Server.Auth
import IAM.Server.Context
import IAM.Server.DB
import IAM.Server.Handlers
import IAM.Session
import IAM.User
import IAM.UserIdentifier


server :: DB db => Ctx db -> Server API
server = signedAPI


signedAPI :: DB db => Ctx db -> Server SignedAPI
signedAPI ctx auth
  = callerAPI ctx auth
  :<|> usersAPI ctx auth
  :<|> groupsAPI ctx auth
  :<|> policiesAPI ctx auth
  :<|> authorizeAPI ctx auth
  :<|> loginRequestHandler ctx auth


callerAPI :: DB db => Ctx db -> Auth -> Server UserAPI
callerAPI ctx auth
  = getUserHandler ctx auth callerId
  :<|> updateUserHandler ctx auth callerId
  :<|> deleteUserHandler ctx auth callerId
  :<|> loginRequestsAPI ctx auth callerId
  :<|> userPublicKeysAPI ctx auth callerId
  :<|> userPolicyAPI ctx auth callerId
  :<|> userSessionsAPI ctx auth callerId
  where
  callerId = UserIdentifier callerUid Nothing Nothing
  callerUid =
    case authN auth of
      Just auth' -> Just $ userId $ authUser auth'
      Nothing -> Nothing


usersAPI :: DB db => Ctx db -> Auth -> Server UsersAPI
usersAPI ctx auth
  = listUsersHandler ctx auth
  :<|> createUserHandler ctx auth
  :<|> userAPI ctx auth


userAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server UserAPI
userAPI ctx auth uid
  = getUserHandler ctx auth uid
  :<|> updateUserHandler ctx auth uid
  :<|> deleteUserHandler ctx auth uid
  :<|> loginRequestsAPI ctx auth uid
  :<|> userPublicKeysAPI ctx auth uid
  :<|> userPolicyAPI ctx auth uid
  :<|> userSessionsAPI ctx auth uid


loginRequestsAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server LoginsAPI
loginRequestsAPI ctx auth uid
  = listLoginRequestsHandler ctx auth uid
  :<|> loginRequestAPI ctx auth uid


loginRequestAPI :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> LoginRequestId -> Server LoginAPI
loginRequestAPI ctx auth uid lid
  = getLoginRequestHandler ctx auth uid lid
  :<|> deleteLoginRequestHandler ctx auth uid lid
  :<|> updateLoginRequestHandler ctx auth uid lid LoginRequestDenied
  :<|> updateLoginRequestHandler ctx auth uid lid LoginRequestGranted


userPublicKeysAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server PublicKeysAPI
userPublicKeysAPI ctx auth uid
  = listUserPublicKeysHandler ctx auth uid
  :<|> createUserPublicKeyHandler ctx auth uid
  :<|> userPublicKeyAPI ctx auth uid


userPublicKeyAPI ::
  DB db => Ctx db -> Auth -> UserIdentifier -> PublicKey' -> Server PublicKeyAPI
userPublicKeyAPI ctx auth uid key
  = getUserPublicKeyHandler ctx auth uid key
  :<|> deleteUserPublicKeyHandler ctx auth uid key


userPolicyAPI ::
  DB db => Ctx db -> Auth -> UserIdentifier -> PolicyIdentifier -> Server UserPolicyAPI
userPolicyAPI ctx auth uid pid
  = createUserPolicyAttachmentHandler ctx auth uid pid
  :<|> deleteUserPolicyAttachmentHandler ctx auth uid pid


userSessionsAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server UserSessionsAPI
userSessionsAPI ctx auth uid
  = createSessionHandler ctx auth uid
  :<|> listUserSessionsHandler ctx auth uid
  :<|> userSessionAPI ctx auth uid


userSessionAPI ::
  DB db => Ctx db -> Auth -> UserIdentifier -> SessionId -> Server UserSessionAPI
userSessionAPI ctx auth uid sid
  = getUserSessionHandler ctx auth uid sid
  :<|> deleteUserSessionHandler ctx auth uid sid
  :<|> refreshUserSessionHandler ctx auth uid sid


groupsAPI :: DB db => Ctx db -> Auth -> Server GroupsAPI
groupsAPI ctx auth
  = listGroupsHandler ctx auth
  :<|> createGroupHandler ctx auth
  :<|> groupAPI ctx auth


groupAPI :: DB db => Ctx db -> Auth -> GroupIdentifier -> Server GroupAPI
groupAPI ctx auth gid
  = getGroupHandler ctx auth gid
  :<|> deleteGroupHandler ctx auth gid
  :<|> groupPolicyAPI ctx auth gid
  :<|> groupMembershipAPI ctx auth gid


groupPolicyAPI ::
  DB db => Ctx db -> Auth -> GroupIdentifier -> PolicyIdentifier -> Server GroupPolicyAPI
groupPolicyAPI ctx auth gid pid
  = createGroupPolicyAttachmentHandler ctx auth gid pid
  :<|> deleteGroupPolicyAttachmentHandler ctx auth gid pid


groupMembershipAPI ::
  DB db => Ctx db -> Auth -> GroupIdentifier -> UserIdentifier -> Server MembershipAPI
groupMembershipAPI ctx auth gid uid
  = createMembershipHandler ctx auth gid uid
  :<|> deleteMembershipHandler ctx auth gid uid


policiesAPI :: DB db => Ctx db -> Auth -> Server PoliciesAPI
policiesAPI ctx auth
  = listPoliciesHandler ctx auth
  :<|> createPolicyHandler ctx auth
  :<|> policyAPI ctx auth


policyAPI :: DB db => Ctx db -> Auth -> PolicyIdentifier -> Server PolicyAPI
policyAPI ctx auth pid
  = getPolicyHandler ctx auth pid
  :<|> deletePolicyHandler ctx auth pid


authorizeAPI :: DB db => Ctx db -> Auth -> Server AuthorizeAPI
authorizeAPI ctx _ = authorizeHandler ctx
