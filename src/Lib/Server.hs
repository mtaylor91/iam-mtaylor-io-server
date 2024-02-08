module Lib.Server ( app, startApp ) where

import Network.Wai
import Network.Wai.Handler.Warp
import Servant

import Lib.API
import Lib.DB
import Lib.Handlers
import Lib.IAM

startApp :: DB db => db -> Int -> IO ()
startApp db port = run port $ app db

app :: DB db => db -> Application
app db = serve api $ server db

server :: DB db => db -> Server API
server db = usersAPI db :<|> groupsAPI db :<|> membershipsAPI db

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

membershipsAPI :: DB db => db -> Server MembershipsAPI
membershipsAPI db
  = createMembershipHandler db
  :<|> deleteMembershipHandler db
