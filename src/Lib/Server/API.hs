module Lib.Server.API
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

import Data.UUID
import Network.Wai.Handler.Warp
import Servant

import Lib.API
import Lib.IAM
import Lib.Server.Auth
import Lib.Server.Handlers
import Lib.Server.IAM.DB

app :: DB db => db -> Application
app db = serveWithContext api (authContext db) $ server db

startApp :: DB db => db -> Int -> IO ()
startApp db port = run port $ app db

server :: DB db => db -> Server API
server db
  = usersAPI db
  :<|> groupsAPI db
  :<|> policiesAPI db
  :<|> membershipsAPI db

usersAPI :: DB db => db -> Auth -> Server UsersAPI
usersAPI db caller
  = listUsersHandler db caller
  :<|> createUserHandler db caller
  :<|> userAPI db caller

userAPI :: DB db => db -> Auth -> UserId -> Server UserAPI
userAPI db caller uid
  = getUserHandler db caller uid
  :<|> deleteUserHandler db caller uid
  :<|> userPolicyAPI db caller uid

userPolicyAPI :: DB db => db -> Auth -> UserId -> UUID -> Server UserPolicyAPI
userPolicyAPI db caller uid pid
  = createUserPolicyAttachmentHandler db caller uid pid
  :<|> deleteUserPolicyAttachmentHandler db caller uid pid

groupsAPI :: DB db => db -> Auth -> Server GroupsAPI
groupsAPI db caller
  = listGroupsHandler db caller
  :<|> createGroupHandler db caller
  :<|> groupAPI db caller

groupAPI :: DB db => db -> Auth -> GroupId -> Server GroupAPI
groupAPI db caller gid
  = getGroupHandler db caller gid
  :<|> deleteGroupHandler db caller gid
  :<|> groupPolicyAPI db caller gid

groupPolicyAPI :: DB db => db -> Auth -> GroupId -> UUID -> Server GroupPolicyAPI
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
