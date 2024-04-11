{-# LANGUAGE OverloadedStrings #-}
module IAM.Authentication
  ( module IAM.Authentication
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.UUID (UUID, toText)
import Network.HTTP.Types

import IAM.Policy (Action(..))


-- | Action that the request is trying to perform
actionFromMethod :: Method -> Action
actionFromMethod method = case parseMethod method of
  Right m -> case m of
    GET -> Read
    POST -> Write
    HEAD -> Read
    PUT -> Write
    DELETE -> Write
    TRACE -> Read
    CONNECT -> Read
    OPTIONS -> Read
    PATCH -> Write
  Left _ -> Write


-- | String to sign to authenticate the request
stringToSign ::
  Method ->
  ByteString ->
  ByteString ->
  ByteString ->
  UUID ->
  Maybe Text ->
  ByteString
stringToSign method host path query requestId Nothing
  = method <> "\n"
  <> host <> "\n"
  <> path <> "\n"
  <> query <> "\n"
  <> encodeUtf8 (toText requestId)
stringToSign method host path query requestId (Just token)
  = method <> "\n"
  <> host <> "\n"
  <> path <> "\n"
  <> query <> "\n"
  <> encodeUtf8 (toText requestId) <> "\n"
  <> encodeUtf8 token
