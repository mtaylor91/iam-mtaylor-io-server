{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module IAM.API
  ( API
  , UserAPI
  , UsersAPI
  , UserPolicyAPI
  , UserSessionsAPI
  , UserSessionAPI
  , GroupAPI
  , GroupsAPI
  , GroupPolicyAPI
  , MembershipAPI
  , PolicyAPI
  , PoliciesAPI
  , AuthorizeAPI
  , api
  , iamAPI
  ) where

import Data.UUID
import Servant

import IAM.Authorization
import IAM.Group
import IAM.GroupPolicy
import IAM.Identifiers
import IAM.Membership
import IAM.Policy
import IAM.Session
import IAM.User
import IAM.UserPolicy


type API = AuthProtect "signature-auth" :> IAMAPI


type IAMAPI
  = ( "user" :> UserAPI
  :<|> ("users" :> UsersAPI)
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "policies" :> PoliciesAPI )
  :<|> ( "authorize" :> AuthorizeAPI )
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
  :<|> "sessions" :> UserSessionsAPI
    )

type UserPolicyAPI
  = ( PostCreated '[JSON] UserPolicyAttachment
  :<|> Delete '[JSON] UserPolicyAttachment
    )

type UserSessionsAPI
  = ( PostCreated '[JSON] Session
  :<|> QueryParam "offset" Int :> QueryParam "limit" Int :> Get '[JSON] [Session]
  :<|> ( Capture "session" SessionId :> UserSessionAPI )
    )

type UserSessionAPI
  = ( Get '[JSON] Session
  :<|> Delete '[JSON] Session
  :<|> "refresh" :> Post '[JSON] Session
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
  :<|> "members" :> Capture "user" UserIdentifier :> MembershipAPI
    )

type GroupPolicyAPI
  = ( PostCreated '[JSON] GroupPolicyAttachment
  :<|> Delete '[JSON] GroupPolicyAttachment
    )

type MembershipAPI
  = ( PostCreated '[JSON] Membership
  :<|> Delete '[JSON] Membership
    )

type PoliciesAPI
  = ( QueryParam "offset" Int :> QueryParam "limit" Int :> Get '[JSON] [UUID]
  :<|> ( ReqBody '[JSON] Policy :> PostCreated '[JSON] Policy )
  :<|> ( Capture "policy" UUID :> PolicyAPI )
    )

type PolicyAPI
  = ( Get '[JSON] Policy
  :<|> Delete '[JSON] Policy
    )

type AuthorizeAPI
  = ReqBody '[JSON] AuthorizationRequest :> Post '[JSON] AuthorizationResponse


api :: Proxy API
api = Proxy


iamAPI :: Proxy IAMAPI
iamAPI = Proxy
