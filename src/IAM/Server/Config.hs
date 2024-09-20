module IAM.Server.Config
  ( configAdminEmail
  , configAdminPublicKey
  , loadEnvConfig
  , readEnvConfig
  ) where

import Control.Exception
import Data.ByteString (ByteString)
import Data.Text as T
import Data.Text.Encoding
import System.Environment
import Text.Read

import IAM.Config


configAdminEmail :: IO String
configAdminEmail = loadNamespaceEnvConfig "ADMIN_EMAIL"


configAdminPublicKey :: IO String
configAdminPublicKey = loadNamespaceEnvConfig "ADMIN_PUBLIC_KEY"


loadEnvConfig :: String -> IO ByteString
loadEnvConfig key = do
  maybeValue <- lookupEnv key
  case maybeValue of
    Nothing -> throw $ userError $ key ++ " environment variable not set"
    Just val -> return $ encodeUtf8 $ T.pack val


readEnvConfig :: Read t => String -> IO t
readEnvConfig key = do
  maybeValue <- lookupEnv key
  case maybeValue of
    Nothing -> throw $ userError $ key ++ " environment variable not set"
    Just val -> case readMaybe val of
      Nothing -> throw $ userError $ key ++ " environment variable not a valid value"
      Just val' -> return val'
