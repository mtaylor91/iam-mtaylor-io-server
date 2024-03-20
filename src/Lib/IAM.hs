{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
module Lib.IAM
  ( User(..)
  , UserId(..)
  , UserPrincipal(..)
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


data UserId
  = UserUUID !UUID
  | UserEmail !Text
  deriving (Eq, Show)

$(deriveJSON defaultOptions { sumEncoding = UntaggedValue } ''UserId)

instance FromHttpApiData UserId where
  parseUrlPiece = Right . UserEmail

instance ToHttpApiData UserId where
  toUrlPiece (UserEmail email) = email
  toUrlPiece (UserUUID uuid) = toText uuid


data GroupId
  = GroupUUID !UUID
  | GroupName !Text
  deriving (Eq, Show)

$(deriveJSON defaultOptions { sumEncoding = UntaggedValue } ''GroupId)

instance FromHttpApiData GroupId where
  parseUrlPiece = Right . GroupName

instance ToHttpApiData GroupId where
  toUrlPiece (GroupName name) = name
  toUrlPiece (GroupUUID uuid) = toText uuid


data User = User
  { userId :: !UserId
  , userGroups :: ![GroupId]
  , userPolicies :: ![UUID]
  , userPublicKeys :: ![PublicKey]
  } deriving (Eq, Show)

instance FromJSON User where
  parseJSON (Object obj) = do
    email <- obj .:? "email"
    uuid <- obj .:? "uuid"
    groups <- obj .: "groups"
    policies <- obj .: "policies"
    publicKeys <- obj .: "publicKeys"
    case (email, uuid, decodePublicKeys publicKeys) of
      (Just e, Nothing, Just pks) -> return $ User (UserEmail e) groups policies pks
      (Nothing, Just u, Just pks) -> return $ User (UserUUID u) groups policies pks
      (_, _, _) -> fail "Invalid JSON"
    where
      decodePublicKeys :: [Text] -> Maybe [PublicKey]
      decodePublicKeys (x:xs) =
        case decodeBase64 $ encodeUtf8 x of
          Left _ -> Nothing
          Right bs -> case decodePublicKeys xs of
            Nothing -> Nothing
            Just pks -> Just $ PublicKey bs : pks
      decodePublicKeys [] = Just []
  parseJSON _ = fail "Invalid JSON"

instance ToJSON User where
  toJSON (User (UserEmail email) groups policies pks) = object
    [ "email" .= email
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= fmap (encodeBase64 . unPublicKey) pks
    ]
  toJSON (User (UserUUID uuid) groups policies pks) = object
    [ "uuid" .= uuid
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= fmap (encodeBase64 . unPublicKey) pks
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


data UserPrincipal = UserPrincipal
  { principal :: !UserId
  , publicKey :: !PublicKey
  } deriving (Eq, Show)

instance FromJSON UserPrincipal where
  parseJSON (Object obj) = do
    email <- obj .:? "email"
    uuid <- obj .:? "uuid"
    publicKeyBase64 <- obj .: "publicKey"
    case decodeBase64 $ encodeUtf8 publicKeyBase64 of
      Left _ -> fail "Invalid public key"
      Right bs -> case (email, uuid) of
        (Just e, Nothing) -> return $ UserPrincipal (UserEmail e) $ PublicKey bs
        (Nothing, Just u) -> return $ UserPrincipal (UserUUID u) $ PublicKey bs
        (_, _) -> fail "Invalid JSON"
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserPrincipal where
  toJSON (UserPrincipal (UserEmail email) (PublicKey bs)) = object
    [ "email" .= email
    , "publicKey" .= encodeBase64 bs
    ]
  toJSON (UserPrincipal (UserUUID uuid) (PublicKey bs)) = object
    [ "uuid" .= uuid
    , "publicKey" .= encodeBase64 bs
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

$(deriveJSON defaultOptions ''Policy)


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
