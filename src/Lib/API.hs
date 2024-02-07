{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module Lib.API ( api, usersAPI, groupsAPI, API ) where

import Data.Text
import Servant

import Lib.DB
import Lib.Group
import Lib.Handlers
import Lib.User

type API
  = ( "users" :> UsersAPI
  :<|> ( "groups" :> GroupsAPI )
    )

type UsersAPI
  = ( Get '[JSON] [User]
  :<|> ( ReqBody '[JSON] User :> Post '[JSON] User )
  :<|> ( Capture "email" Text :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> ( ReqBody '[JSON] User :> Put '[JSON] User )
  :<|> Delete '[JSON] (Maybe User)
    )

type GroupsAPI
  = ( Get '[JSON] [Group]
  :<|> ( ReqBody '[JSON] Group :> Post '[JSON] Group )
  :<|> ( Capture "group" Text :> GroupAPI )
    )

type GroupAPI
  = ( Get '[JSON] Group
  :<|> ( ReqBody '[JSON] Group :> Put '[JSON] Group )
  :<|> Delete '[JSON] (Maybe Group)
    )

usersAPI :: DB db => db -> Server UsersAPI
usersAPI db
  = listUsersHandler db
  :<|> createUserHandler db
  :<|> userAPI db

userAPI :: DB db => db -> Text -> Server UserAPI
userAPI db email
  = getUserHandler db email
  :<|> updateUserHandler db email
  :<|> deleteUserHandler db email

groupsAPI :: DB db => db -> Server GroupsAPI
groupsAPI db
  = listGroupsHandler db
  :<|> createGroupHandler db
  :<|> groupAPI db

groupAPI :: DB db => db -> Text -> Server GroupAPI
groupAPI db name
  = getGroupHandler db name
  :<|> updateGroupHandler db name
  :<|> deleteGroupHandler db name

api :: Proxy API
api = Proxy
