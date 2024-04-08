{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
module IAM.Types
  ( module IAM.Types
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
import Text.Read (readMaybe)


newtype UserId = UserUUID UUID deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''UserId)


newtype GroupId = GroupUUID UUID deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''GroupId)


data UserIdentifier
  = UserEmail !Text
  | UserId !UserId
  | UserIdAndEmail !UserId !Text
  deriving (Eq, Show)

instance FromHttpApiData UserIdentifier where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ UserId $ UserUUID uuid
    Nothing -> Right $ UserEmail s

instance ToHttpApiData UserIdentifier where
  toUrlPiece (UserEmail email) = email
  toUrlPiece (UserId (UserUUID uuid)) = toText uuid
  toUrlPiece (UserIdAndEmail (UserUUID uuid) _) = toText uuid

instance FromJSON UserIdentifier where
  parseJSON (Object obj) = do
    uuid <- obj .:? "id"
    email <- obj .:? "email"
    case (uuid, email) of
      (Just (Just uuid'), Just email') -> return $ UserIdAndEmail (UserUUID uuid') email'
      (Just (Just uuid'), Nothing) -> return $ UserId $ UserUUID uuid'
      (Nothing, Just email') -> return $ UserEmail email'
      (_, _) -> fail "Invalid JSON"
  parseJSON (String s) = case readMaybe $ unpack s of
    Just uuid -> return $ UserId $ UserUUID uuid
    Nothing -> return $ UserEmail s
  parseJSON _ = fail "Invalid JSON"

instance ToJSON UserIdentifier where
  toJSON (UserEmail email) = object ["email" .= email]
  toJSON (UserId (UserUUID uuid)) = object ["id" .= uuid]
  toJSON (UserIdAndEmail (UserUUID uuid) email) = object
    [ "id" .= uuid
    , "email" .= email
    ]

unUserIdentifier :: UserIdentifier -> Either Text UserId
unUserIdentifier (UserEmail email) = Left email
unUserIdentifier (UserId uid) = Right uid
unUserIdentifier (UserIdAndEmail uid _) = Right uid

unUserIdentifierEmail :: UserIdentifier -> Maybe Text
unUserIdentifierEmail (UserEmail email) = Just email
unUserIdentifierEmail (UserIdAndEmail _ email) = Just email
unUserIdentifierEmail _ = Nothing

userIdentifierToText :: UserIdentifier -> Text
userIdentifierToText (UserEmail email) = email
userIdentifierToText (UserId (UserUUID uuid)) = toText uuid
userIdentifierToText (UserIdAndEmail (UserUUID uuid) _) = toText uuid


data GroupIdentifier
  = GroupName !Text
  | GroupId !GroupId
  | GroupIdAndName !GroupId !Text
  deriving (Eq, Show)

instance FromHttpApiData GroupIdentifier where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ GroupId $ GroupUUID uuid
    Nothing -> Right $ GroupName s

instance ToHttpApiData GroupIdentifier where
  toUrlPiece (GroupName name) = name
  toUrlPiece (GroupId (GroupUUID uuid)) = toText uuid
  toUrlPiece (GroupIdAndName (GroupUUID uuid) _) = toText uuid

instance FromJSON GroupIdentifier where
  parseJSON (Object obj) = do
    uuid <- obj .:? "id"
    name <- obj .:? "name"
    case (uuid, name) of
      (Just (Just uuid'), Just name') -> return $ GroupIdAndName (GroupUUID uuid') name'
      (Just (Just uuid'), Nothing) -> return $ GroupId $ GroupUUID uuid'
      (Nothing, Just name') -> return $ GroupName name'
      (_, _) -> fail "Invalid JSON"
  parseJSON (String s) = case readMaybe $ unpack s of
    Just uuid -> return $ GroupId $ GroupUUID uuid
    Nothing -> return $ GroupName s
  parseJSON _ = fail "Invalid JSON"

instance ToJSON GroupIdentifier where
  toJSON (GroupName name) = object ["name" .= name]
  toJSON (GroupId (GroupUUID uuid)) = object ["id" .= uuid]
  toJSON (GroupIdAndName (GroupUUID uuid) name) = object
    [ "id" .= uuid
    , "name" .= name
    ]

unGroupIdentifier :: GroupIdentifier -> Either Text GroupId
unGroupIdentifier (GroupName name) = Left name
unGroupIdentifier (GroupId gid) = Right gid
unGroupIdentifier (GroupIdAndName gid _) = Right gid

unGroupIdentifierName :: GroupIdentifier -> Maybe Text
unGroupIdentifierName (GroupName name) = Just name
unGroupIdentifierName (GroupIdAndName _ name) = Just name
unGroupIdentifierName _ = Nothing

groupIdentifierToText :: GroupIdentifier -> Text
groupIdentifierToText (GroupName name) = name
groupIdentifierToText (GroupId (GroupUUID uuid)) = toText uuid
groupIdentifierToText (GroupIdAndName (GroupUUID uuid) _) = toText uuid


data UserPublicKey = UserPublicKey
  { userPublicKey :: !PublicKey
  , userPublicKeyDescription :: !Text
  } deriving (Eq, Show)


instance FromJSON UserPublicKey where
  parseJSON (Object obj) = do
    key <- obj .: "key"
    description <- obj .: "description"
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
  , userEmail :: !(Maybe Text)
  , userGroups :: ![GroupIdentifier]
  , userPolicies :: ![UUID]
  , userPublicKeys :: ![UserPublicKey]
  } deriving (Eq, Show)

instance FromJSON User where
  parseJSON (Object obj) = do
    uid <- obj .: "id"
    groups <- obj .: "groups"
    policies <- obj .: "policies"
    publicKeys <- obj .: "publicKeys"
    maybeEmail <- obj .:? "email"
    return $ User uid maybeEmail groups policies publicKeys
  parseJSON _ = fail "Invalid JSON"

instance ToJSON User where
  toJSON (User (UserUUID uuid) email groups policies pks) = object
    [ "id" .= uuid
    , "email" .= email
    , "groups" .= groups
    , "policies" .= policies
    , "publicKeys" .= toJSON pks
    ]


data Group = Group
  { groupId :: !GroupId
  , groupName :: !(Maybe Text)
  , groupUsers :: ![UserIdentifier]
  , groupPolicies :: ![UUID]
  } deriving (Eq, Show)

instance FromJSON Group where
  parseJSON (Object obj) = do
    uuid <- obj .: "id"
    maybeName <- obj .:? "name"
    maybeUsers <- obj .:? "users"
    maybePolicies <- obj .:? "policies"
    let users = fromMaybe [] maybeUsers
    let policies = fromMaybe [] maybePolicies
    return $ Group uuid maybeName users policies
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Group where
  toJSON (Group (GroupUUID uuid) maybeName users policies) = object
    [ "id" .= uuid
    , "name" .= maybeName
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
  , hostname :: !Text
  , statements :: ![Rule]
  } deriving (Eq, Show)

instance FromJSON Policy where
  parseJSON (Object obj) = do
    id' <- obj .: "id"
    hostname' <- obj .: "hostname"
    statements' <- obj .: "statements"
    return $ Policy id' hostname' statements'
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Policy where
  toJSON (Policy id' hostname' statements') = object
    [ "id" .= id'
    , "hostname" .= hostname'
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


data AuthorizationRequest = AuthorizationRequest
  { authorizationRequestUser :: !UserIdentifier
  , authorizationRequestAction :: !Action
  , authorizationRequestResource :: !Text
  , authorizationRequestHost :: !Text
  } deriving (Eq, Show)


instance FromJSON AuthorizationRequest where
  parseJSON (Object obj) = do
    u <- obj .: "user"
    a <- obj .: "action"
    r <- obj .: "resource"
    h <- obj .: "host"
    return $ AuthorizationRequest u a r h
  parseJSON _ = fail "Invalid JSON"

instance ToJSON AuthorizationRequest where
  toJSON (AuthorizationRequest u a r h) = object
    [ "user" .= u
    , "action" .= a
    , "resource" .= r
    , "host" .= h
    ]


newtype AuthorizationResponse = AuthorizationResponse
  { authorizationResponseEffect :: Effect } deriving (Eq, Show)

instance FromJSON AuthorizationResponse where
  parseJSON (Object obj) = do
    e <- obj .: "effect"
    return $ AuthorizationResponse e
  parseJSON _ = fail "Invalid JSON"

instance ToJSON AuthorizationResponse where
  toJSON (AuthorizationResponse e) = object ["effect" .= e]


data Range = Range
  { rangeOffset :: !Int
  , rangeLimit :: !(Maybe Int)
  } deriving (Eq, Show)
