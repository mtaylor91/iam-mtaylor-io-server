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

import Data.Text (Text)
import Servant

import IAM.Authorization
import IAM.Group
import IAM.GroupPolicy
import IAM.GroupIdentifier
import IAM.ListResponse
import IAM.Membership
import IAM.Policy
import IAM.Session
import IAM.User
import IAM.UserPolicy
import IAM.UserIdentifier


type API = AuthProtect "signature-auth" :> IAMAPI


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
  = ( QueryParam "search" Text :> QueryParam "sort" SortUsersBy :> ListAPI UserIdentifier
  :<|> ( ReqBody '[JSON] User :> PostCreated '[JSON] User )
  :<|> ( Capture "user" UserIdentifier :> UserAPI )
    )

type UserAPI
  = ( Get '[JSON] User
  :<|> Delete '[JSON] User
  :<|> "policies" :> Capture "policy" PolicyIdentifier :> UserPolicyAPI
  :<|> "sessions" :> UserSessionsAPI
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
  = ( QueryParam "search" Text :> ListAPI GroupIdentifier
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
  = ( QueryParam "search" Text :> ListAPI PolicyIdentifier
  :<|> ( ReqBody '[JSON] Policy :> PostCreated '[JSON] Policy )
  :<|> ( Capture "policy" PolicyIdentifier :> PolicyAPI )
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
