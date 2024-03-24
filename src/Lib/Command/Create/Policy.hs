{-# LANGUAGE OverloadedStrings #-}
module Lib.Command.Create.Policy
  ( createPolicy
  , createPolicyOptions
  , CreatePolicy(..)
  ) where

import Control.Exception
import Data.Text as T
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import Lib.Client.Auth
import Lib.Client.Util
import Lib.IAM
import qualified Lib.Client


data CreatePolicy
  = CreatePolicy
    { createPolicyUUID :: !(Maybe Text)
    , createPolicyAllowRead :: ![Text]
    , createPolicyAllowWrite :: ![Text]
    , createPolicyDenyRead :: ![Text]
    , createPolicyDenyWrite :: ![Text]
    } deriving (Show)


createPolicy :: CreatePolicy -> IO ()
createPolicy createPolicyInfo =
  case createPolicyUUID createPolicyInfo of
    Nothing -> nextRandom >>= createPolicyWithUUID createPolicyInfo
    Just uuid -> case readMaybe $ unpack uuid of
      Just uuid' -> createPolicyWithUUID createPolicyInfo uuid'
      Nothing -> throw $ userError "Invalid UUID"


createPolicyWithUUID :: CreatePolicy -> UUID -> IO ()
createPolicyWithUUID createPolicyInfo uuid = createPolicy' $ Policy uuid stmts where
  stmts = allowStmts ++ denyStmts
  allowStmts = allowReadStmts ++ allowWriteStmts
  allowReadStmts = Rule Allow Read <$> createPolicyAllowRead createPolicyInfo
  allowWriteStmts = Rule Allow Write <$> createPolicyAllowWrite createPolicyInfo
  denyStmts = denyReadStmts ++ denyWriteStmts
  denyReadStmts = Rule Deny Read <$> createPolicyDenyRead createPolicyInfo
  denyWriteStmts = Rule Deny Write <$> createPolicyDenyWrite createPolicyInfo


createPolicy' :: Policy -> IO ()
createPolicy' policy = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  result <- runClientM (Lib.Client.createPolicy policy) $ mkClientEnv mgr url
  case result of
    Right _ ->
      putStrLn $ unpack $ toText $ policyId policy
    Left err ->
      handleClientError err


createPolicyOptions :: Parser CreatePolicy
createPolicyOptions = CreatePolicy
  <$> optional (argument str
      ( metavar "UUID"
     <> help "Policy UUID"
      ))
  <*> many (strOption
      ( long "allow-read"
     <> metavar "RESOURCE"
     <> help "Allow read access to resource"
      ))
  <*> many (strOption
      ( long "allow-write"
     <> metavar "RESOURCE"
     <> help "Allow write access to resource"
      ))
  <*> many (strOption
      ( long "deny-read"
     <> metavar "RESOURCE"
     <> help "Deny read access to resource"
      ))
  <*> many (strOption
      ( long "deny-write"
     <> metavar "RESOURCE"
     <> help "Deny write access to resource"
      ))
