{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module IAM.ListResponse
  ( module IAM.ListResponse
  ) where

import Data.Aeson


data ListResponse a = ListResponse
  { items :: ![a]
  , limit :: !Int
  , offset :: !Int
  , total :: !Int
  } deriving (Eq, Show)


instance (FromJSON a) => FromJSON (ListResponse a) where
  parseJSON = withObject "ListResponse" $ \o -> do
    items <- o .: "items"
    limit <- o .: "limit"
    offset <- o .: "offset"
    total <- o .: "total"
    return ListResponse {..}


instance (ToJSON a) => ToJSON (ListResponse a) where
  toJSON ListResponse {..} = object
    [ "items" .= items
    , "limit" .= limit
    , "offset" .= offset
    , "total" .= total
    ]
