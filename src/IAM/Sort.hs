{-# LANGUAGE OverloadedStrings #-}
module IAM.Sort
  ( module IAM.Sort
  ) where

import Data.Text (Text)
import Servant


data SortOrder = Ascending | Descending


instance FromHttpApiData SortOrder where
  parseUrlPiece = maybe (Left "Invalid sort") Right . parseSortOrder


instance ToHttpApiData SortOrder where
  toUrlPiece = sortOrderText


sortOrderText :: SortOrder -> Text
sortOrderText Ascending = "asc"
sortOrderText Descending = "desc"


parseSortOrder :: Text -> Maybe SortOrder
parseSortOrder "asc" = Just Ascending
parseSortOrder "desc" = Just Descending
parseSortOrder _ = Nothing


data SortUsersBy = SortUsersById | SortUsersByName | SortUsersByEmail


instance FromHttpApiData SortUsersBy where
  parseUrlPiece = maybe (Left "Invalid sort") Right . parseSortUsersBy


instance ToHttpApiData SortUsersBy where
  toUrlPiece = sortUserByText


sortUserByText :: SortUsersBy -> Text
sortUserByText SortUsersById = "id"
sortUserByText SortUsersByName = "name"
sortUserByText SortUsersByEmail = "email"


parseSortUsersBy :: Text -> Maybe SortUsersBy
parseSortUsersBy "id" = Just SortUsersById
parseSortUsersBy "name" = Just SortUsersByName
parseSortUsersBy "email" = Just SortUsersByEmail
parseSortUsersBy _ = Nothing


data SortGroupsBy = SortGroupsById | SortGroupsByName


instance FromHttpApiData SortGroupsBy where
  parseUrlPiece = maybe (Left "Invalid sort") Right . parseSortGroupsBy


instance ToHttpApiData SortGroupsBy where
  toUrlPiece = sortGroupByText


sortGroupByText :: SortGroupsBy -> Text
sortGroupByText SortGroupsById = "id"
sortGroupByText SortGroupsByName = "name"


parseSortGroupsBy :: Text -> Maybe SortGroupsBy
parseSortGroupsBy "id" = Just SortGroupsById
parseSortGroupsBy "name" = Just SortGroupsByName
parseSortGroupsBy _ = Nothing


data SortPoliciesBy = SortPoliciesById | SortPoliciesByName


instance FromHttpApiData SortPoliciesBy where
  parseUrlPiece = maybe (Left "Invalid sort") Right . parseSortPoliciesBy


instance ToHttpApiData SortPoliciesBy where
  toUrlPiece = sortPolicyByText


sortPolicyByText :: SortPoliciesBy -> Text
sortPolicyByText SortPoliciesById = "id"
sortPolicyByText SortPoliciesByName = "name"


parseSortPoliciesBy :: Text -> Maybe SortPoliciesBy
parseSortPoliciesBy "id" = Just SortPoliciesById
parseSortPoliciesBy "name" = Just SortPoliciesByName
parseSortPoliciesBy _ = Nothing
