module Lib.Config
  ( configEmail
  , configPublicKey
  , configSecretKey
  , configURL
  , envPrefix
  ) where

import Control.Exception
import System.Environment


envPrefix :: String
envPrefix = "API_MTAYLOR_IO"


configEmail :: IO String
configEmail = loadEnvConfig "EMAIL"


configPublicKey :: IO String
configPublicKey = loadEnvConfig "PUBLIC_KEY"


configSecretKey :: IO String
configSecretKey = loadEnvConfig "SECRET_KEY"


configURL :: IO String
configURL = do
  maybeValue <- lookupEnvConfig "URL"
  case maybeValue of
    Nothing -> return "https://api.mtaylor.io"
    Just value -> return value


loadEnvConfig :: String -> IO String
loadEnvConfig key = do
  let key' = envPrefix ++ "_" ++ key
  maybeValue <- lookupEnv key'
  case maybeValue of
    Nothing -> throw $ userError $ key' ++ " environment variable not set"
    Just value -> return value


lookupEnvConfig :: String -> IO (Maybe String)
lookupEnvConfig key = do
  let key' = envPrefix ++ "_" ++ key
  lookupEnv key'
