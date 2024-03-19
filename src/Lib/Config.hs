module Lib.Config
  ( configEmail
  , configPublicKey
  , configSecretKey
  , configURL
  , envPrefix
  , headerPrefix
  , printUserShellVars
  ) where

import Control.Exception
import Crypto.Sign.Ed25519
import System.Environment
import qualified Data.Text as T

import Lib.Util


envPrefix :: String
envPrefix = "API_MTAYLOR_IO"


headerPrefix :: String
headerPrefix = "X-MTaylor-IO"


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


printUserShellVars :: T.Text -> PublicKey -> SecretKey -> IO ()
printUserShellVars email pk sk = do
  let email' = T.unpack email
  let pk' = T.unpack (encodePublicKey pk)
  let sk' = T.unpack (encodeSecretKey sk)
  let prefix = "export " ++ envPrefix ++ "_"
  putStrLn $ prefix ++ "EMAIL=\"" ++ email' ++ "\""
  putStrLn $ prefix ++ "PUBLIC_KEY=\"" ++ pk' ++ "\""
  putStrLn $ prefix ++ "SECRET_KEY=\"" ++ sk' ++ "\""
  return ()
