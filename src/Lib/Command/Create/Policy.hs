{-# LANGUAGE OverloadedStrings #-}
module Lib.Command.Create.Policy
  ( createPolicy
  , createPolicyOptions
  , CreatePolicy(..)
  ) where

import Control.Exception
import Data.Aeson
import Data.ByteString.Lazy as LBS
import Data.Text as T
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import System.IO

import Lib.Client.Auth
import Lib.Client.Util
import Lib.IAM (Policy(..))
import qualified Lib.Client


newtype CreatePolicy
  = CreatePolicy
    { policyDocumentSource :: Text
    } deriving (Show)


createPolicy :: CreatePolicy -> IO ()
createPolicy createPolicyInfo =
  case policyDocumentSource createPolicyInfo of
    "-" -> createPolicyFromStdin createPolicyInfo
    _ -> createPolicyFromFilePath createPolicyInfo


createPolicyFromStdin :: CreatePolicy -> IO ()
createPolicyFromStdin createPolicyInfo = createPolicyFromFile createPolicyInfo stdin


createPolicyFromFilePath :: CreatePolicy -> IO ()
createPolicyFromFilePath createPolicyInfo =
  withFile (T.unpack $ policyDocumentSource createPolicyInfo) ReadMode $
    createPolicyFromFile createPolicyInfo


createPolicyFromFile :: CreatePolicy -> Handle -> IO ()
createPolicyFromFile createPolicyInfo h = do
  policyDocument <- LBS.hGetContents h
  -- Decode the policy document
  case decode policyDocument of
    Just policy -> do
      putStrLn $ "Creating policy with ID " ++ show createPolicyInfo
      createPolicy' policy
    Nothing -> do
      putStrLn "Invalid policy document"
      throwIO $ userError "Invalid policy document"


createPolicy' :: Policy -> IO ()
createPolicy' policy = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  result <- runClientM (Lib.Client.createPolicy policy) $ mkClientEnv mgr url
  case result of
    Right _ ->
      putStrLn "Policy created"
    Left err ->
      handleClientError err


createPolicyOptions :: Parser CreatePolicy
createPolicyOptions = CreatePolicy
  <$> argument str
      ( metavar "DOCUMENT"
     <> help "Policy document source"
      )
