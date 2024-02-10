{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module Lib.API
  ( api
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
import Servant

import Lib.IAM

type API
  = ( "users" :> AuthProtect "signature-auth" :> UsersAPI
  :<|> ( "groups" :> AuthProtect "signature-auth" :> GroupsAPI )
  :<|> ( "policies" :> AuthProtect "signature-auth" :> PoliciesAPI )
  :<|> ( "memberships" :> AuthProtect "signature-auth" :> MembershipsAPI )
    )

type UsersAPI
  = ( Get '[JSON] [UserId]
  :<|> ( ReqBody '[JSON] UserPrincipal :> PostCreated '[JSON] UserPrincipal )
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
  = ( Get '[JSON] [Policy]
  :<|> ( ReqBody '[JSON] Policy :> PostCreated '[JSON] Policy )
  :<|> ( Capture "policy" UUID :> PolicyAPI )
    )

type PolicyAPI
  = ( Get '[JSON] Policy
  :<|> Delete '[JSON] Policy
    )

api :: Proxy API
api = Proxy
