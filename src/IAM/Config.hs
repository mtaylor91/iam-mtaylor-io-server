module IAM.Config
  ( configEmail
  , configUserIdentifier
  , configPublicKey
  , configSecretKey
  , configMaybeSessionToken
  , configSessionId
  , configURL
  , envPrefix
  , headerPrefix
  , printUserNameShellVars
  , printUserEmailShellVars
  , printUserUUIDShellVars
  ) where

import Control.Exception
import Crypto.Sign.Ed25519
import Data.UUID
import System.Environment
import qualified Data.Text as T

import IAM.Session
import IAM.Util


envPrefix :: String
envPrefix = "MTAYLOR_IO"


headerPrefix :: String
headerPrefix = "X-MTaylor-IO"


configUserIdentifier :: IO String
configUserIdentifier = do
  maybeUUID <- lookupNamespaceEnvConfig "UUID"
  maybeUsername <- lookupNamespaceEnvConfig "USERNAME"
  maybeEmail <- lookupNamespaceEnvConfig "EMAIL"
  case (maybeUUID, maybeUsername, maybeEmail) of
    (Just uuid, _, _) -> return uuid
    (_, Just username, _) -> return username
    (_, _, Just email) -> return email
    _ -> throw $ userError $ "One of "
      ++ envPrefix ++ "_UUID, "
      ++ envPrefix ++ "_USERNAME, or "
      ++ envPrefix ++ "_EMAIL must be set"


configEmail :: IO String
configEmail = loadNamespaceEnvConfig "EMAIL"


configPublicKey :: IO String
configPublicKey = loadNamespaceEnvConfig "PUBLIC_KEY"


configSecretKey :: IO String
configSecretKey = loadNamespaceEnvConfig "SECRET_KEY"


configSessionId :: IO SessionId
configSessionId = do
  t <- loadNamespaceEnvConfig "SESSION_ID"
  case fromText (T.pack t) of
    Nothing -> throw $ userError "Invalid session ID"
    Just uuid -> return $ SessionUUID uuid


configMaybeSessionToken :: IO (Maybe String)
configMaybeSessionToken = lookupNamespaceEnvConfig "SESSION_TOKEN"


configURL :: IO String
configURL = do
  maybeValue <- lookupNamespaceEnvConfig "URL"
  case maybeValue of
    Nothing -> return "https://iam.mtaylor.io"
    Just value -> return value


loadNamespaceEnvConfig :: String -> IO String
loadNamespaceEnvConfig key = do
  let key' = envPrefix ++ "_" ++ key
  maybeValue <- lookupEnv key'
  case maybeValue of
    Nothing -> throw $ userError $ key' ++ " environment variable not set"
    Just value -> return value


lookupNamespaceEnvConfig :: String -> IO (Maybe String)
lookupNamespaceEnvConfig key = do
  let key' = envPrefix ++ "_" ++ key
  lookupEnv key'


printUserNameShellVars :: T.Text -> PublicKey -> SecretKey -> IO ()
printUserNameShellVars name pk sk = do
  let name' = T.unpack name
  let pk' = T.unpack (encodePublicKey pk)
  let sk' = T.unpack (encodeSecretKey sk)
  let prefix = "export " ++ envPrefix ++ "_"
  putStrLn $ prefix ++ "USERNAME=\"" ++ name' ++ "\""
  putStrLn $ prefix ++ "PUBLIC_KEY=\"" ++ pk' ++ "\""
  putStrLn $ prefix ++ "SECRET_KEY=\"" ++ sk' ++ "\""
  return ()


printUserEmailShellVars :: T.Text -> PublicKey -> SecretKey -> IO ()
printUserEmailShellVars email pk sk = do
  let email' = T.unpack email
  let pk' = T.unpack (encodePublicKey pk)
  let sk' = T.unpack (encodeSecretKey sk)
  let prefix = "export " ++ envPrefix ++ "_"
  putStrLn $ prefix ++ "EMAIL=\"" ++ email' ++ "\""
  putStrLn $ prefix ++ "PUBLIC_KEY=\"" ++ pk' ++ "\""
  putStrLn $ prefix ++ "SECRET_KEY=\"" ++ sk' ++ "\""
  return ()


printUserUUIDShellVars :: UUID -> PublicKey -> SecretKey -> IO ()
printUserUUIDShellVars uuid pk sk = do
  let uuid' = toString uuid
  let pk' = T.unpack (encodePublicKey pk)
  let sk' = T.unpack (encodeSecretKey sk)
  let prefix = "export " ++ envPrefix ++ "_"
  putStrLn $ prefix ++ "UUID=\"" ++ uuid' ++ "\""
  putStrLn $ prefix ++ "PUBLIC_KEY=\"" ++ pk' ++ "\""
  putStrLn $ prefix ++ "SECRET_KEY=\"" ++ sk' ++ "\""
  return ()
