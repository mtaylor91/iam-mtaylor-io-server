{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module Lib.API ( api, usersAPI, API ) where

import Data.Text
import Servant

import Lib.DB
import Lib.Handlers
import Lib.User

type API = "users" :> UsersAPI

type UsersAPI
  = ( Get '[JSON] [User]
  :<|> ( ReqBody '[JSON] User :> Post '[JSON] User )
  :<|> ( Capture "email" Text :> UserAPI )
  )

type UserAPI
  = Get '[JSON] User
  :<|> ( ReqBody '[JSON] User :> Put '[JSON] User )
  :<|> Delete '[JSON] (Maybe User)

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

api :: Proxy API
api = Proxy
