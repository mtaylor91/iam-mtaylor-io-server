{-# LANGUAGE OverloadedStrings #-}
module Lib.IAM.Policy
  ( policyAuthorizes
  , resourceMatches
  ) where

import Data.Text hiding (any)

import Lib.IAM


-- | policyAuthorizes returns whether a policy authorizes an action.
policyAuthorizes :: Policy -> Action -> Text -> Bool
policyAuthorizes p a r = any allow $ statements p where
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
