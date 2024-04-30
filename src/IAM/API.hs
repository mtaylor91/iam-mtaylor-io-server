{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE TypeOperators   #-}
module IAM.API
  ( API
  , LoginAPI
  , LoginsAPI
  , UserAPI
  , UsersAPI
  , PublicKeysAPI
  , PublicKeyAPI
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
import IAM.PublicKey
import IAM.Session
import IAM.Sort
import IAM.User
import IAM.UserIdentifier
import IAM.UserPolicy
import IAM.UserPublicKey


type API = SignedAPI


type SignedAPI = AuthProtect "signature-auth" :> IAMAPI


type ListAPI a
  = QueryParam "offset" Int
  :> QueryParam "limit" Int
  :> Get '[JSON] (ListResponse a)


type LoginHandlerAPI =
  ReqBody '[JSON] LoginRequest :> Post '[JSON] (LoginResponse CreateSession)


type IAMAPI
  = ( "user" :> UserAPI
  :<|> ("users" :> UsersAPI)
  :<|> ( "groups" :> GroupsAPI )
  :<|> ( "policies" :> PoliciesAPI )
  :<|> ( "authorize" :> AuthorizeAPI )
  :<|> ( "login" :> LoginHandlerAPI )
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
  :<|> ReqBody '[JSON] UserUpdate :> Put '[JSON] User
  :<|> Delete '[JSON] User
  :<|> "login-requests" :> LoginsAPI
  :<|> "public-keys" :> PublicKeysAPI
  :<|> "policies" :> Capture "policy" PolicyIdentifier :> UserPolicyAPI
  :<|> "sessions" :> UserSessionsAPI
    )

type LoginsAPI
  = ( ListAPI (LoginResponse SessionId)
  :<|> Capture "login-request" LoginRequestId :> LoginAPI
    )

type LoginAPI
  = ( Get '[JSON] (LoginResponse SessionId)
  :<|> Delete '[JSON] (LoginResponse SessionId)
  :<|> "deny" :> Post '[JSON] (LoginResponse SessionId)
  :<|> "grant" :> Post '[JSON] (LoginResponse SessionId)
    )

type PublicKeysAPI
  = ( ListAPI UserPublicKey
  :<|> ReqBody '[JSON] UserPublicKey :> PostCreated '[JSON] UserPublicKey
  :<|> Capture "key" PublicKey' :> PublicKeyAPI
    )

type PublicKeyAPI
  = ( Get '[JSON] UserPublicKey
  :<|> Delete '[JSON] UserPublicKey
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


api :: Proxy API
api = Proxy


iamAPI :: Proxy IAMAPI
iamAPI = Proxy
