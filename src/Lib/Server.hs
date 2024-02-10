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

usersAPI :: DB db => db -> Server UsersAPI
usersAPI db
  = listUsersHandler db
  :<|> createUserHandler db
  :<|> userAPI db

userAPI :: DB db => db -> UserId -> Server UserAPI
userAPI db user
  = getUserHandler db user
  :<|> deleteUserHandler db user

groupsAPI :: DB db => db -> Server GroupsAPI
groupsAPI db
  = listGroupsHandler db
  :<|> createGroupHandler db
  :<|> groupAPI db

groupAPI :: DB db => db -> GroupId -> Server GroupAPI
groupAPI db group
  = getGroupHandler db group
  :<|> deleteGroupHandler db group

policiesAPI :: DB db => db -> Server PoliciesAPI
policiesAPI db
  = listPoliciesHandler db
  :<|> createPolicyHandler db
  :<|> policyAPI db

policyAPI :: DB db => db -> UUID -> Server PolicyAPI
policyAPI db pid
  = getPolicyHandler db pid
  :<|> deletePolicyHandler db pid

membershipsAPI :: DB db => db -> Server MembershipsAPI
membershipsAPI db
  = createMembershipHandler db
  :<|> deleteMembershipHandler db
