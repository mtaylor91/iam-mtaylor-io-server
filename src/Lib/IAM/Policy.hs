{-# LANGUAGE OverloadedStrings #-}
module Lib.IAM.Policy
  ( isAuthorized
  , policyRules
  , resourceMatches
  ) where

import Data.Text hiding (any, concatMap)

import Lib.IAM


policyRules :: [Policy] -> [Rule]
policyRules = concatMap statements


-- | isAuthorized returns whether a set of rules authorizes an action.
isAuthorized :: Action -> Text -> [Rule] -> Bool
isAuthorized a r = any allow where
  allow :: Rule -> Bool
  allow rule
    = effect rule == Allow
    && a == action rule
    && resourceMatches r (resource rule)


-- | resourceMatches returns whether a resource matches a pattern.
resourceMatches :: Text -> Text -> Bool
resourceMatches match pattern
  | "*" `isSuffixOf` pattern = Data.Text.init pattern `isPrefixOf` match
  | pattern == match = True
  | otherwise = False
