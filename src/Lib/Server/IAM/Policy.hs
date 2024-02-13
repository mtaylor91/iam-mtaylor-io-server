{-# LANGUAGE OverloadedStrings #-}
module Lib.Server.IAM.Policy
  ( isAllowedBy
  , isAuthorized
  , policyRules
  , resourceMatches
  ) where

import Data.Text hiding (any, all, concatMap)

import Lib.Server.IAM


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
