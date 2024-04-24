{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.GroupIdentifier
  ( module IAM.GroupIdentifier
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text
import Data.UUID
import Servant
import Text.Read (readMaybe)


newtype GroupId = GroupUUID { unGroupId :: UUID } deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''GroupId)

instance Ord GroupId where
  compare (GroupUUID a) (GroupUUID b) = compare a b


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

unGroupIdentifierId :: GroupIdentifier -> Maybe GroupId
unGroupIdentifierId (GroupId gid) = Just gid
unGroupIdentifierId (GroupIdAndName gid _) = Just gid
unGroupIdentifierId _ = Nothing

unGroupIdentifierName :: GroupIdentifier -> Maybe Text
unGroupIdentifierName (GroupName name) = Just name
unGroupIdentifierName (GroupIdAndName _ name) = Just name
unGroupIdentifierName _ = Nothing

groupIdentifierToText :: GroupIdentifier -> Text
groupIdentifierToText (GroupName name) = name
groupIdentifierToText (GroupId (GroupUUID uuid)) = toText uuid
groupIdentifierToText (GroupIdAndName (GroupUUID uuid) _) = toText uuid
