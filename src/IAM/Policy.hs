{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module IAM.Policy
  ( module IAM.Policy
  ) where

import Data.Aeson
import Data.Aeson.TH
import Data.Text hiding (any, all, concatMap)
import Data.UUID


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
resourceMatches :: Text -> Text -> Bool
resourceMatches match pattern
  | "*" `isSuffixOf` pattern = Data.Text.init pattern `isPrefixOf` match
  | pattern == match = True
  | otherwise = False
