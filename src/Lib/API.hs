{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module Lib.API
  ( API
  , UserAPI
  , UsersAPI
  , UserPolicyAPI
  , GroupAPI
  , GroupsAPI
  , GroupPolicyAPI
  , MembershipsAPI
  , PolicyAPI
  , PoliciesAPI
  , api
  , iamAPI
  ) where

import Data.UUID
import Servant

import Lib.IAM


type API = AuthProtect "signature-auth" :> IAMAPI


type IAMAPI
  = ( "user" :> UserAPI
  :<|> ("users" :> UsersAPI)
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "policies" :> PoliciesAPI )
  :<|> ( "memberships" :> MembershipsAPI )
    )

type UsersAPI
  = ( Get '[JSON] [UserId]
  :<|> ( ReqBody '[JSON] User :> PostCreated '[JSON] User )
  :<|> ( Capture "user" UserId :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> Delete '[JSON] UserId
  :<|> "policies" :> Capture "policy" UUID :> UserPolicyAPI
    )

type UserPolicyAPI
  = ( PostCreated '[JSON] UserPolicyAttachment
  :<|> Delete '[JSON] UserPolicyAttachment
    )

type GroupsAPI
  = ( Get '[JSON] [GroupId]
  :<|> ( ReqBody '[JSON] Group :> PostCreated '[JSON] Group )
  :<|> ( Capture "group" GroupId :> GroupAPI )
    )

type GroupAPI
  = ( Get '[JSON] Group
  :<|> Delete '[JSON] GroupId
  :<|> "policies" :> Capture "policy" UUID :> GroupPolicyAPI
    )

type GroupPolicyAPI
  = ( PostCreated '[JSON] GroupPolicyAttachment
  :<|> Delete '[JSON] GroupPolicyAttachment
    )

type MembershipsAPI
  = ReqBody '[JSON] Membership :> PostCreated '[JSON] Membership
  :<|> ( Capture "group" GroupId :> Capture "user" UserId :> Delete '[JSON] Membership )

type PoliciesAPI
  = ( Get '[JSON] [UUID]
  :<|> ( ReqBody '[JSON] Policy :> PostCreated '[JSON] Policy )
  :<|> ( Capture "policy" UUID :> PolicyAPI )
    )

type PolicyAPI
  = ( Get '[JSON] Policy
  :<|> Delete '[JSON] Policy
    )

api :: Proxy API
api = Proxy


iamAPI :: Proxy IAMAPI
iamAPI = Proxy
