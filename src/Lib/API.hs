{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module Lib.API
  ( api
  , API
  , UserAPI
  , GroupAPI
  , UsersAPI
  , GroupsAPI
  , MembershipsAPI
  ) where

import Servant

import Lib.IAM

type API
  = ( "users" :> UsersAPI
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "memberships" :> MembershipsAPI )
    )

type UsersAPI
  = ( Get '[JSON] [UserId]
  :<|> ( ReqBody '[JSON] UserId :> PostCreated '[JSON] UserId )
  :<|> ( Capture "email" UserId :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> Delete '[JSON] UserId
    )

type GroupsAPI
  = ( Get '[JSON] [GroupId]
  :<|> ( ReqBody '[JSON] GroupId :> PostCreated '[JSON] GroupId )
  :<|> ( Capture "group" GroupId :> GroupAPI )
    )

type GroupAPI
  = ( Get '[JSON] Group
  :<|> Delete '[JSON] GroupId
    )

type MembershipsAPI
  = ReqBody '[JSON] Membership :> PostCreated '[JSON] Membership
  :<|> ( Capture "group" GroupId :> Capture "user" UserId :> Delete '[JSON] Membership )

api :: Proxy API
api = Proxy
