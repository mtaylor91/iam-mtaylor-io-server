{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.Identifiers
  ( module IAM.Identifiers
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text
import Data.UUID
import Servant
import Text.Read (readMaybe)


newtype UserId = UserUUID { unUserId :: UUID } deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''UserId)


newtype GroupId = GroupUUID { unGroupId :: UUID } deriving (Eq, Show)

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
