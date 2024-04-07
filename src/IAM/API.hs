{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module IAM.API
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

import IAM.Types


type API = AuthProtect "signature-auth" :> IAMAPI


type IAMAPI
  = ( "user" :> UserAPI
  :<|> ("users" :> UsersAPI)
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "policies" :> PoliciesAPI )
  :<|> ( "memberships" :> MembershipsAPI )
    )

type UsersAPI
  = ( QueryParam "offset" Int :> QueryParam "limit" Int :> Get '[JSON] [UserIdentifier]
  :<|> ( ReqBody '[JSON] User :> PostCreated '[JSON] User )
  :<|> ( Capture "user" UserIdentifier :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> Delete '[JSON] User
  :<|> "policies" :> Capture "policy" UUID :> UserPolicyAPI
    )

type UserPolicyAPI
  = ( PostCreated '[JSON] UserPolicyAttachment
  :<|> Delete '[JSON] UserPolicyAttachment
    )

type GroupsAPI
  = ( QueryParam "offset" Int :> QueryParam "limit" Int :> Get '[JSON] [GroupIdentifier]
  :<|> ( ReqBody '[JSON] Group :> PostCreated '[JSON] Group )
  :<|> ( Capture "group" GroupIdentifier :> GroupAPI )
    )

type GroupAPI
  = ( Get '[JSON] Group
  :<|> Delete '[JSON] Group
  :<|> "policies" :> Capture "policy" UUID :> GroupPolicyAPI
    )

type GroupPolicyAPI
  = ( PostCreated '[JSON] GroupPolicyAttachment
  :<|> Delete '[JSON] GroupPolicyAttachment
    )

type MembershipsAPI
  = ReqBody '[JSON] Membership :> PostCreated '[JSON] Membership
  :<|> ( Capture "group" GroupIdentifier :> Capture "user" UserIdentifier
    :> Delete '[JSON] Membership )

type PoliciesAPI
  = ( QueryParam "offset" Int :> QueryParam "limit" Int :> Get '[JSON] [UUID]
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
