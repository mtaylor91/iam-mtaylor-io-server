{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.UserIdentifier
  ( module IAM.UserIdentifier
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text
import Data.UUID
import Servant
import Text.Read (readMaybe)


newtype UserId = UserUUID { unUserId :: UUID } deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''UserId)


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
