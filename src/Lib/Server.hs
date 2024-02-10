module Lib.Server ( app, startApp ) where

import Data.UUID
import Network.Wai
import Network.Wai.Handler.Warp
import Servant

import Lib.API
import Lib.Auth
import Lib.Handlers
import Lib.IAM
import Lib.IAM.DB

startApp :: DB db => db -> Int -> IO ()
startApp db port = run port $ app db

app :: DB db => db -> Application
app db = serveWithContext api (authContext db) $ server db

server :: DB db => db -> Server API
server db
  = usersAPI db
  :<|> groupsAPI db
  :<|> policiesAPI db
  :<|> membershipsAPI db

usersAPI :: DB db => db -> User -> Server UsersAPI
usersAPI db caller
  = listUsersHandler db caller
  :<|> createUserHandler db caller
  :<|> userAPI db caller

userAPI :: DB db => db -> User -> UserId -> Server UserAPI
userAPI db caller uid
  = getUserHandler db caller uid
  :<|> deleteUserHandler db caller uid

groupsAPI :: DB db => db -> User -> Server GroupsAPI
groupsAPI db caller
  = listGroupsHandler db caller
  :<|> createGroupHandler db caller
  :<|> groupAPI db caller

groupAPI :: DB db => db -> User -> GroupId -> Server GroupAPI
groupAPI db caller gid
  = getGroupHandler db caller gid
  :<|> deleteGroupHandler db caller gid

policiesAPI :: DB db => db -> User -> Server PoliciesAPI
policiesAPI db caller
  = listPoliciesHandler db caller
  :<|> createPolicyHandler db caller
  :<|> policyAPI db caller

policyAPI :: DB db => db -> User -> UUID -> Server PolicyAPI
policyAPI db caller pid
  = getPolicyHandler db caller pid
  :<|> deletePolicyHandler db caller pid

membershipsAPI :: DB db => db -> User -> Server MembershipsAPI
membershipsAPI db caller
  = createMembershipHandler db caller
  :<|> deleteMembershipHandler db caller
