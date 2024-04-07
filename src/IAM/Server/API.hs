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
  , MembershipsAPI
  , UserPolicyAPI
  , GroupPolicyAPI
  ) where

import Data.Text
import Data.UUID
import Network.Wai.Handler.Warp
import Servant

import IAM.API
import IAM.Server.Auth
import IAM.Server.DB
import IAM.Server.Handlers
import IAM.Types

app :: DB db => Text -> db -> Application
app host db = serveWithContext api (authContext host db) $ server db

startApp :: DB db => Int -> Text -> db -> IO ()
startApp port host db = run port $ app host db

server :: DB db => db -> Server API
server db caller
  = callerAPI db caller
  :<|> usersAPI db caller
  :<|> groupsAPI db caller
  :<|> policiesAPI db caller
  :<|> membershipsAPI db caller
  :<|> authorizeAPI db caller

callerAPI :: DB db => db -> Auth -> Server UserAPI
callerAPI db caller
  = getUserHandler db caller (UserId $ userId $ authUser $ authentication caller)
  :<|> deleteUserHandler db caller (UserId $ userId $ authUser $ authentication caller)
  :<|> userPolicyAPI db caller (UserId $ userId $ authUser $ authentication caller)

usersAPI :: DB db => db -> Auth -> Server UsersAPI
usersAPI db caller
  = listUsersHandler db caller
  :<|> createUserHandler db caller
  :<|> userAPI db caller

userAPI :: DB db => db -> Auth -> UserIdentifier -> Server UserAPI
userAPI db caller uid
  = getUserHandler db caller uid
  :<|> deleteUserHandler db caller uid
  :<|> userPolicyAPI db caller uid

userPolicyAPI :: DB db => db -> Auth -> UserIdentifier -> UUID -> Server UserPolicyAPI
userPolicyAPI db caller uid pid
  = createUserPolicyAttachmentHandler db caller uid pid
  :<|> deleteUserPolicyAttachmentHandler db caller uid pid

groupsAPI :: DB db => db -> Auth -> Server GroupsAPI
groupsAPI db caller
  = listGroupsHandler db caller
  :<|> createGroupHandler db caller
  :<|> groupAPI db caller

groupAPI :: DB db => db -> Auth -> GroupIdentifier -> Server GroupAPI
groupAPI db caller gid
  = getGroupHandler db caller gid
  :<|> deleteGroupHandler db caller gid
  :<|> groupPolicyAPI db caller gid

groupPolicyAPI :: DB db => db -> Auth -> GroupIdentifier -> UUID -> Server GroupPolicyAPI
groupPolicyAPI db caller gid pid
  = createGroupPolicyAttachmentHandler db caller gid pid
  :<|> deleteGroupPolicyAttachmentHandler db caller gid pid

policiesAPI :: DB db => db -> Auth -> Server PoliciesAPI
policiesAPI db caller
  = listPoliciesHandler db caller
  :<|> createPolicyHandler db caller
  :<|> policyAPI db caller

policyAPI :: DB db => db -> Auth -> UUID -> Server PolicyAPI
policyAPI db caller pid
  = getPolicyHandler db caller pid
  :<|> deletePolicyHandler db caller pid

membershipsAPI :: DB db => db -> Auth -> Server MembershipsAPI
membershipsAPI db caller
  = createMembershipHandler db caller
  :<|> deleteMembershipHandler db caller

authorizeAPI :: DB db => db -> Auth -> Server AuthorizeAPI
authorizeAPI db _ = authorizeHandler db
