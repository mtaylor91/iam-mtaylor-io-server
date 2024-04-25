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
import IAM.Server.Auth
import IAM.Server.Context
import IAM.Server.DB
import IAM.Server.Handlers
import IAM.Session
import IAM.User
import IAM.UserIdentifier


server :: DB db => Ctx db -> Server API
server ctx = loginRequestHandler ctx :<|> signedAPI ctx


signedAPI :: DB db => Ctx db -> Server SignedAPI
signedAPI ctx caller
  = callerAPI ctx caller
  :<|> usersAPI ctx caller
  :<|> groupsAPI ctx caller
  :<|> policiesAPI ctx caller
  :<|> authorizeAPI ctx caller


callerAPI :: DB db => Ctx db -> Auth -> Server UserAPI
callerAPI ctx caller
  = getUserHandler ctx caller callerId
  :<|> deleteUserHandler ctx caller callerId
  :<|> loginRequestsAPI ctx caller callerId
  :<|> userPolicyAPI ctx caller callerId
  :<|> userSessionsAPI ctx caller callerId
  where
  callerId = UserIdentifier callerUid Nothing Nothing
  callerUid = Just $ userId $ authUser $ authentication caller


usersAPI :: DB db => Ctx db -> Auth -> Server UsersAPI
usersAPI ctx caller
  = listUsersHandler ctx caller
  :<|> createUserHandler ctx caller
  :<|> userAPI ctx caller


userAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server UserAPI
userAPI ctx caller uid
  = getUserHandler ctx caller uid
  :<|> deleteUserHandler ctx caller uid
  :<|> loginRequestsAPI ctx caller uid
  :<|> userPolicyAPI ctx caller uid
  :<|> userSessionsAPI ctx caller uid


loginRequestsAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server LoginRequestsAPI
loginRequestsAPI ctx caller uid
  = listLoginRequestsHandler ctx caller uid
  :<|> loginRequestAPI ctx caller uid


loginRequestAPI :: DB db =>
  Ctx db -> Auth -> UserIdentifier -> LoginRequestId -> Server LoginRequestAPI
loginRequestAPI ctx caller uid lid
  = getLoginRequestHandler ctx caller uid lid
  :<|> deleteLoginRequestHandler ctx caller uid lid
  :<|> updateLoginRequestHandler ctx caller uid lid LoginRequestDenied
  :<|> updateLoginRequestHandler ctx caller uid lid LoginRequestGranted


userPolicyAPI ::
  DB db => Ctx db -> Auth -> UserIdentifier -> PolicyIdentifier -> Server UserPolicyAPI
userPolicyAPI ctx caller uid pid
  = createUserPolicyAttachmentHandler ctx caller uid pid
  :<|> deleteUserPolicyAttachmentHandler ctx caller uid pid


userSessionsAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server UserSessionsAPI
userSessionsAPI ctx caller uid
  = createSessionHandler ctx caller uid
  :<|> listUserSessionsHandler ctx caller uid
  :<|> userSessionAPI ctx caller uid


userSessionAPI ::
  DB db => Ctx db -> Auth -> UserIdentifier -> SessionId -> Server UserSessionAPI
userSessionAPI ctx caller uid sid
  = getUserSessionHandler ctx caller uid sid
  :<|> deleteUserSessionHandler ctx caller uid sid
  :<|> refreshUserSessionHandler ctx caller uid sid


groupsAPI :: DB db => Ctx db -> Auth -> Server GroupsAPI
groupsAPI ctx caller
  = listGroupsHandler ctx caller
  :<|> createGroupHandler ctx caller
  :<|> groupAPI ctx caller


groupAPI :: DB db => Ctx db -> Auth -> GroupIdentifier -> Server GroupAPI
groupAPI ctx caller gid
  = getGroupHandler ctx caller gid
  :<|> deleteGroupHandler ctx caller gid
  :<|> groupPolicyAPI ctx caller gid
  :<|> groupMembershipAPI ctx caller gid


groupPolicyAPI ::
  DB db => Ctx db -> Auth -> GroupIdentifier -> PolicyIdentifier -> Server GroupPolicyAPI
groupPolicyAPI ctx caller gid pid
  = createGroupPolicyAttachmentHandler ctx caller gid pid
  :<|> deleteGroupPolicyAttachmentHandler ctx caller gid pid


groupMembershipAPI ::
  DB db => Ctx db -> Auth -> GroupIdentifier -> UserIdentifier -> Server MembershipAPI
groupMembershipAPI ctx caller gid uid
  = createMembershipHandler ctx caller gid uid
  :<|> deleteMembershipHandler ctx caller gid uid


policiesAPI :: DB db => Ctx db -> Auth -> Server PoliciesAPI
policiesAPI ctx caller
  = listPoliciesHandler ctx caller
  :<|> createPolicyHandler ctx caller
  :<|> policyAPI ctx caller


policyAPI :: DB db => Ctx db -> Auth -> PolicyIdentifier -> Server PolicyAPI
policyAPI ctx caller pid
  = getPolicyHandler ctx caller pid
  :<|> deletePolicyHandler ctx caller pid


authorizeAPI :: DB db => Ctx db -> Auth -> Server AuthorizeAPI
authorizeAPI ctx _ = authorizeHandler ctx
