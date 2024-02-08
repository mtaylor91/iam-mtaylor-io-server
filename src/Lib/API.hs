{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module Lib.API ( api, usersAPI, groupsAPI, membershipsAPI, API ) where

import Servant

import Lib.DB
import Lib.Handlers
import Lib.IAM

type API
  = ( "users" :> UsersAPI
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "memberships" :> MembershipsAPI )
    )

type UsersAPI
  = ( Get '[JSON] [UserId]
  :<|> ( ReqBody '[JSON] UserId :> Post '[JSON] UserId )
  :<|> ( Capture "email" UserId :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> Delete '[JSON] UserId
    )

type GroupsAPI
  = ( Get '[JSON] [GroupId]
  :<|> ( ReqBody '[JSON] GroupId :> Post '[JSON] GroupId )
  :<|> ( Capture "group" GroupId :> GroupAPI )
    )

type GroupAPI
  = ( Get '[JSON] Group
  :<|> Delete '[JSON] GroupId
    )

type MembershipsAPI
  = ReqBody '[JSON] Membership :> Post '[JSON] Membership
  :<|> ( Capture "group" GroupId :> Capture "user" UserId :> Delete '[JSON] Membership )

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

api :: Proxy API
api = Proxy
