{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module IAM.API
  ( API
  , LoginAPI
  , LoginRequestAPI
  , LoginRequestsAPI
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
  , SignedAPI
  , api
  , iamAPI
  ) where

import Data.Text (Text)
import Servant

import IAM.Authorization
import IAM.Group
import IAM.GroupPolicy
import IAM.GroupIdentifier
import IAM.ListResponse
import IAM.Login
import IAM.Membership
import IAM.Policy
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserPolicy
import IAM.UserIdentifier


type API = LoginAPI :<|> SignedAPI


type SignedAPI = AuthProtect "signature-auth" :> IAMAPI


type ListAPI a
  = QueryParam "offset" Int
  :> QueryParam "limit" Int
  :> Get '[JSON] (ListResponse a)


type IAMAPI
  = ( "user" :> UserAPI
  :<|> ("users" :> UsersAPI)
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "policies" :> PoliciesAPI )
  :<|> ( "authorize" :> AuthorizeAPI )
    )

type UsersAPI
  = ( QueryParam "search" Text
    :> QueryParam "sort" SortUsersBy
    :> QueryParam "order" SortOrder
    :> ListAPI UserIdentifier
  :<|> ( ReqBody '[JSON] User :> PostCreated '[JSON] User )
  :<|> ( Capture "user" UserIdentifier :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> Delete '[JSON] User
  :<|> "login-requests" :> LoginRequestsAPI
  :<|> "policies" :> Capture "policy" PolicyIdentifier :> UserPolicyAPI
  :<|> "sessions" :> UserSessionsAPI
    )

type LoginRequestsAPI
  = ( ListAPI LoginRequest
  :<|> Capture "login-request" LoginRequestId :> LoginRequestAPI
    )

type LoginRequestAPI
  = ( Get '[JSON] LoginRequest
  :<|> Delete '[JSON] LoginRequest
  :<|> "deny" :> Post '[JSON] LoginRequest
  :<|> "grant" :> Post '[JSON] LoginRequest
    )

type UserPolicyAPI
  = ( PostCreated '[JSON] UserPolicyAttachment
  :<|> Delete '[JSON] UserPolicyAttachment
    )

type UserSessionsAPI
  = ( PostCreated '[JSON] CreateSession
  :<|> ListAPI Session
  :<|> ( Capture "session" SessionId :> UserSessionAPI )
    )

type UserSessionAPI
  = ( Get '[JSON] Session
  :<|> Delete '[JSON] Session
  :<|> "refresh" :> Post '[JSON] Session
    )

type GroupsAPI
  = ( QueryParam "search" Text
    :> QueryParam "sort" SortGroupsBy
    :> QueryParam "order" SortOrder
    :> ListAPI GroupIdentifier
  :<|> ( ReqBody '[JSON] Group :> PostCreated '[JSON] Group )
  :<|> ( Capture "group" GroupIdentifier :> GroupAPI )
    )

type GroupAPI
  = ( Get '[JSON] Group
  :<|> Delete '[JSON] Group
  :<|> "policies" :> Capture "policy" PolicyIdentifier :> GroupPolicyAPI
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
  = ( QueryParam "search" Text
    :> QueryParam "sort" SortPoliciesBy
    :> QueryParam "order" SortOrder
    :> ListAPI PolicyIdentifier
  :<|> ( ReqBody '[JSON] Policy :> PostCreated '[JSON] Policy )
  :<|> ( Capture "policy" PolicyIdentifier :> PolicyAPI )
    )

type PolicyAPI
  = ( Get '[JSON] Policy
  :<|> Delete '[JSON] Policy
    )

type AuthorizeAPI
  = ReqBody '[JSON] AuthorizationRequest :> Post '[JSON] AuthorizationResponse


type LoginAPI
  = ReqBody '[JSON] LoginRequest :> Post '[JSON] LoginResponse


api :: Proxy API
api = Proxy


iamAPI :: Proxy IAMAPI
iamAPI = Proxy
