{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.Policy
  ( module IAM.Policy
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text hiding (any, all, concatMap)
import Data.UUID
import Servant
import Text.Read (readMaybe)


newtype PolicyId = PolicyUUID { unPolicyId :: UUID } deriving (Eq, Show)

$(deriveJSON defaultOptions { unwrapUnaryRecords = True } ''PolicyId)

instance FromHttpApiData PolicyId where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ PolicyUUID uuid
    Nothing -> Left "Invalid UUID"

instance ToHttpApiData PolicyId where
  toUrlPiece (PolicyUUID uuid) = toText uuid

instance Ord PolicyId where
  compare (PolicyUUID a) (PolicyUUID b) = compare a b


data PolicyIdentifier
  = PolicyName !Text
  | PolicyId !PolicyId
  | PolicyIdAndName !PolicyId !Text
  deriving (Eq, Show)

instance FromHttpApiData PolicyIdentifier where
  parseUrlPiece s = case readMaybe $ unpack s of
    Just uuid -> Right $ PolicyId $ PolicyUUID uuid
    Nothing -> Right $ PolicyName s

instance ToHttpApiData PolicyIdentifier where
  toUrlPiece (PolicyName name) = name
  toUrlPiece (PolicyId (PolicyUUID uuid)) = toText uuid
  toUrlPiece (PolicyIdAndName (PolicyUUID uuid) _) = toText uuid

instance FromJSON PolicyIdentifier where
  parseJSON (Object obj) = do
    uuid <- obj .:? "id"
    name <- obj .:? "name"
    case (uuid, name) of
      (Just (Just uuid'), Just name') -> return $ PolicyIdAndName (PolicyUUID uuid') name'
      (Just (Just uuid'), Nothing) -> return $ PolicyId $ PolicyUUID uuid'
      (Nothing, Just name') -> return $ PolicyName name'
      (_, _) -> fail "Invalid JSON"
  parseJSON (String s) = case readMaybe $ unpack s of
    Just uuid -> return $ PolicyId $ PolicyUUID uuid
    Nothing -> return $ PolicyName s
  parseJSON _ = fail "Invalid JSON"

instance ToJSON PolicyIdentifier where
  toJSON (PolicyName name) = object ["name" .= name]
  toJSON (PolicyId (PolicyUUID uuid)) = object ["id" .= uuid]
  toJSON (PolicyIdAndName (PolicyUUID uuid) name) = object
    [ "id" .= uuid
    , "name" .= name
    ]

unPolicyIdentifier :: PolicyIdentifier -> Either Text PolicyId
unPolicyIdentifier (PolicyName name) = Left name
unPolicyIdentifier (PolicyId gid) = Right gid
unPolicyIdentifier (PolicyIdAndName gid _) = Right gid

unPolicyIdentifierId :: PolicyIdentifier -> Maybe PolicyId
unPolicyIdentifierId (PolicyId gid) = Just gid
unPolicyIdentifierId (PolicyIdAndName gid _) = Just gid
unPolicyIdentifierId _ = Nothing

unPolicyIdentifierName :: PolicyIdentifier -> Maybe Text
unPolicyIdentifierName (PolicyName name) = Just name
unPolicyIdentifierName (PolicyIdAndName _ name) = Just name
unPolicyIdentifierName _ = Nothing

policyIdentifierToText :: PolicyIdentifier -> Text
policyIdentifierToText (PolicyName name) = name
policyIdentifierToText (PolicyId (PolicyUUID uuid)) = toText uuid
policyIdentifierToText (PolicyIdAndName (PolicyUUID uuid) _) = toText uuid


data Effect = Allow | Deny deriving (Eq, Show)

$(deriveJSON defaultOptions ''Effect)


data Action = Read | Write deriving (Eq, Show)

$(deriveJSON defaultOptions ''Action)


data Rule = Rule
  { effect :: !Effect
  , action :: !Action
  , resource :: !Text
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Rule)


data Policy = Policy
  { policyId :: !PolicyId
  , policyName :: !(Maybe Text)
  , hostname :: !Text
  , statements :: ![Rule]
  } deriving (Eq, Show)

instance FromJSON Policy where
  parseJSON (Object obj) = do
    id' <- obj .: "id"
    name' <- obj .:? "name"
    hostname' <- obj .: "hostname"
    statements' <- obj .: "statements"
    return $ Policy id' name' hostname' statements'
  parseJSON _ = fail "Invalid JSON"

instance ToJSON Policy where
  toJSON (Policy id' Nothing hostname' statements') = object
    [ "id" .= id'
    , "hostname" .= hostname'
    , "statements" .= statements'
    ]
  toJSON (Policy id' (Just name) hostname' statements') = object
    [ "id" .= id'
    , "name" .= name
    , "hostname" .= hostname'
    , "statements" .= statements'
    ]


-- | isAllowedBy returns whether a policy is allowed by a set of rules.
isAllowedBy :: Policy -> [Rule] -> Bool
isAllowedBy p rs = all allowed $ statements p where
  allowed :: Rule -> Bool
  allowed r = isAuthorized (action r) (resource r) rs


-- | isAuthorized returns whether a set of rules authorizes an action.
isAuthorized :: Action -> Text -> [Rule] -> Bool
isAuthorized a r s = any allow s && not (any deny s) where
  allow :: Rule -> Bool
  allow rule
    = effect rule == Allow
    && a == action rule
    && resourceMatches r (resource rule)
  deny :: Rule -> Bool
  deny rule
    = effect rule == Deny
    && a == action rule
    && resourceMatches r (resource rule)


policyRules :: [Policy] -> [Rule]
policyRules = concatMap statements


-- | resourceMatches returns whether a resource matches a pattern.
-- The pattern is a slash-separated string.
-- Components of the pattern can be wildcarded with an asterisk.
-- For example, "foo/bar/*" matches "foo/bar/baz".
-- Two asterisks at the end of the pattern match any suffix.
resourceMatches :: Text -> Text -> Bool
resourceMatches match pattern
  = resourceMatches' (splitOn "/" match) (splitOn "/" pattern)


resourceMatches' :: [Text] -> [Text] -> Bool
resourceMatches' [] [] = True
resourceMatches' [] _ = False
resourceMatches' _ [] = False
resourceMatches' (m:ms) (p:ps)
  | p == "**" = True
  | p == "*" = resourceMatches' ms ps
  | m == p = resourceMatches' ms ps
  | otherwise = False
