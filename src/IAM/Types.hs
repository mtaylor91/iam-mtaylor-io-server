{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
module IAM.Types
  ( User(..)
  , UserId(..)
  , UserPublicKey(..)
  , Group(..)
  , GroupId(..)
  , Effect(..)
  , Action(..)
  , Policy(..)
  , Rule(..)
  , UserPolicyAttachment(UserPolicyAttachment)
  , GroupPolicyAttachment(GroupPolicyAttachment)
  , Membership(..)
  ) where

import Crypto.Sign.Ed25519
import Data.Aeson
import Data.Aeson.TH
import Data.ByteString.Base64
import Data.Maybe
import Data.Text
import Data.Text.Encoding
import Data.UUID
import Servant
import Text.Read


data UserId
  = UserUUID !UUID
  | UserEmail !Text
  deriving (Eq, Show)

$(deriveJSON defaultOptions { sumEncoding = UntaggedValue } ''UserId)

instance FromHttpApiData UserId where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ UserUUID uuid
    Nothing -> Right $ UserEmail s

instance ToHttpApiData UserId where
  toUrlPiece (UserEmail email) = email
  toUrlPiece (UserUUID uuid) = toText uuid


data GroupId
  = GroupUUID !UUID
  | GroupName !Text
  deriving (Eq, Show)

$(deriveJSON defaultOptions { sumEncoding = UntaggedValue } ''GroupId)

instance FromHttpApiData GroupId where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ GroupUUID uuid
    Nothing -> Right $ GroupName s

instance ToHttpApiData GroupId where
  toUrlPiece (GroupName name) = name
  toUrlPiece (GroupUUID uuid) = toText uuid


data UserPublicKey = UserPublicKey
  { userPublicKey :: !PublicKey
  , userPublicKeyDescription :: !Text
  } deriving (Eq, Show)


instance FromJSON UserPublicKey where
  parseJSON (Object obj) = do
    description <- obj .: "description"
    key <- obj .: "key"
    case decodeBase64 $ encodeUtf8 key of
      Left _ -> fail "Invalid JSON"
      Right bs -> return $ UserPublicKey (PublicKey bs) description
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserPublicKey where
  toJSON (UserPublicKey key description) = object
    [ "description" .= description
    , "key" .= encodeBase64 (unPublicKey key)
    ]


data User = User
  { userId :: !UserId
  , userGroups :: ![GroupId]
  , userPolicies :: ![UUID]
  , userPublicKeys :: ![UserPublicKey]
  } deriving (Eq, Show)

instance FromJSON User where
  parseJSON (Object obj) = do
    email <- obj .:? "email"
    uuid <- obj .:? "uuid"
    groups <- obj .: "groups"
    policies <- obj .: "policies"
    publicKeys <- obj .: "publicKeys"
    case (email, uuid) of
      (Just e, Nothing) -> return $ User (UserEmail e) groups policies publicKeys
      (Nothing, Just u) -> return $ User (UserUUID u) groups policies publicKeys
      (_, _) -> fail "Invalid JSON"
  parseJSON _ = fail "Invalid JSON"

instance ToJSON User where
  toJSON (User (UserEmail email) groups policies pks) = object
    [ "email" .= email
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= toJSON pks
    ]
  toJSON (User (UserUUID uuid) groups policies pks) = object
    [ "uuid" .= uuid
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= toJSON pks
    ]


data Group = Group
  { groupId :: !GroupId
  , groupUsers :: ![UserId]
  , groupPolicies :: ![UUID]
  } deriving (Eq, Show)

instance FromJSON Group where
  parseJSON (Object obj) = do
    name <- obj .:? "name"
    uuid <- obj .:? "uuid"
    maybeUsers <- obj .:? "users"
    maybePolicies <- obj .:? "policies"
    let users = fromMaybe [] maybeUsers
    let policies = fromMaybe [] maybePolicies
    case (name, uuid) of
      (Just n, Nothing) -> return $ Group (GroupName n) users policies
      (Nothing, Just u) -> return $ Group (GroupUUID u) users policies
      (_, _) -> fail "Invalid JSON"
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Group where
  toJSON (Group (GroupName name) users policies) = object
    [ "name" .= name
    , "users" .= users
    , "policies" .= policies
    ]
  toJSON (Group (GroupUUID uuid) users policies) = object
    [ "uuid" .= uuid
    , "users" .= users
    , "policies" .= policies
    ]


data Membership = Membership
  { membershipUserId :: !UserId
  , membershipGroupId :: !GroupId
  } deriving (Eq, Show)

instance FromJSON Membership where
  parseJSON (Object obj) = do
    u <- obj .: "user"
    g <- obj .: "group"
    return $ Membership u g
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Membership where
  toJSON (Membership u g) = object
    [ "user" .= u
    , "group" .= g
    ]


data Effect = Allow | Deny deriving (Eq, Show)

$(deriveJSON defaultOptions ''Effect)


data Action = Read | Write | Delete deriving (Eq, Show)

$(deriveJSON defaultOptions ''Action)


data Rule = Rule
  { effect :: !Effect
  , action :: !Action
  , resource :: !Text
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Rule)


data Policy = Policy
  { policyId :: !UUID
  , statements :: ![Rule]
  } deriving (Eq, Show)

instance FromJSON Policy where
  parseJSON (Object obj) = do
    id' <- obj .: "id"
    statements' <- obj .: "statements"
    return $ Policy id' statements'
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Policy where
  toJSON (Policy id' statements') = object
    [ "id" .= id'
    , "statements" .= statements'
    ]


data UserPolicyAttachment = UserPolicyAttachment
  { userPolicyAttachmentUserId :: !UserId
  , userPolicyAttachmentPolicyId :: !UUID
  } deriving (Eq, Show)

instance FromJSON UserPolicyAttachment where
  parseJSON (Object obj) = do
    u <- obj .: "user"
    p <- obj .: "policy"
    return $ UserPolicyAttachment u p
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserPolicyAttachment where
  toJSON (UserPolicyAttachment u p) = object
    [ "user" .= u
    , "policy" .= p
    ]


data GroupPolicyAttachment = GroupPolicyAttachment
  { groupPolicyAttachmentGroupId :: !GroupId
  , groupPolicyAttachmentPolicyId :: !UUID
  } deriving (Eq, Show)

instance FromJSON GroupPolicyAttachment where
  parseJSON (Object obj) = do
    g <- obj .: "group"
    p <- obj .: "policy"
    return $ GroupPolicyAttachment g p
  parseJSON _ = fail "Invalid JSON"

instance ToJSON GroupPolicyAttachment where
  toJSON (GroupPolicyAttachment g p) = object
    [ "group" .= g
    , "policy" .= p
    ]
