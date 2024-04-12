module IAM.Server.API
  ( api
  , app
  , startApp
  , API
  , UserAPI
  , GroupAPI
  , UsersAPI
  , GroupsAPI
  , PolicyAPI
  , PoliciesAPI
  , UserPolicyAPI
  , GroupPolicyAPI
  ) where

import Data.Text
import Network.Wai.Handler.Warp
import Servant

import IAM.API
import IAM.Identifiers
import IAM.Policy
import IAM.Server.Auth
import IAM.Server.Context
import IAM.Server.DB
import IAM.Server.Handlers
import IAM.Session
import IAM.User


app :: DB db => Text -> Ctx db -> Application
app host ctx = serveWithContext api (authContext host ctx) $ server ctx

startApp :: DB db => Int -> Text -> Ctx db -> IO ()
startApp port host ctx = run port $ app host ctx

server :: DB db => Ctx db -> Server API
server ctx caller
  = callerAPI ctx caller
  :<|> usersAPI ctx caller
  :<|> groupsAPI ctx caller
  :<|> policiesAPI ctx caller
  :<|> authorizeAPI ctx caller

callerAPI :: DB db => Ctx db -> Auth -> Server UserAPI
callerAPI ctx caller
  = getUserHandler ctx caller (UserId $ userId $ authUser $ authentication caller)
  :<|> deleteUserHandler ctx caller (UserId $ userId $ authUser $ authentication caller)
  :<|> userPolicyAPI ctx caller (UserId $ userId $ authUser $ authentication caller)
  :<|> userSessionsAPI ctx caller (UserId $ userId $ authUser $ authentication caller)

usersAPI :: DB db => Ctx db -> Auth -> Server UsersAPI
usersAPI ctx caller
  = listUsersHandler ctx caller
  :<|> createUserHandler ctx caller
  :<|> userAPI ctx caller

userAPI :: DB db => Ctx db -> Auth -> UserIdentifier -> Server UserAPI
userAPI ctx caller uid
  = getUserHandler ctx caller uid
  :<|> deleteUserHandler ctx caller uid
  :<|> userPolicyAPI ctx caller uid
  :<|> userSessionsAPI ctx caller uid

userPolicyAPI ::
  DB db => Ctx db -> Auth -> UserIdentifier -> PolicyId -> Server UserPolicyAPI
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
  DB db => Ctx db -> Auth -> GroupIdentifier -> PolicyId -> Server GroupPolicyAPI
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

policyAPI :: DB db => Ctx db -> Auth -> PolicyId -> Server PolicyAPI
policyAPI ctx caller pid
  = getPolicyHandler ctx caller pid
  :<|> deletePolicyHandler ctx caller pid

authorizeAPI :: DB db => Ctx db -> Auth -> Server AuthorizeAPI
authorizeAPI ctx _ = authorizeHandler ctx
