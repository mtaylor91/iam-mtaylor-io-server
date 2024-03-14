{-# LANGUAGE OverloadedStrings #-}
module Lib.Command.Create.User (createUser) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding
import qualified Lib.Client
import Lib.IAM (UserId(..), UserPrincipal(..))
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Servant.Client


createUser :: Text -> Maybe Text -> IO ()
createUser email maybePublicKey = do
  url <- serverUrl
  case maybePublicKey of
    Just pk -> do
      createUser' url email pk
    Nothing -> do
      (pk, sk) <- createKeypair
      createUser' url email (encodeBase64 (unPublicKey pk))
      putStrLn $ "Secret key: " ++ unpack (encodeBase64 (unSecretKey sk))


createUser' :: BaseUrl -> Text -> Text -> IO ()
createUser' url email pk = do
  mgr <- newManager defaultManagerSettings
  case decodeBase64 (encodeUtf8 pk) of
    Left _ ->
      putStrLn "Invalid public key: base64 decoding failed"
    Right pk' -> do
      let userPrincipal = UserPrincipal (UserEmail email) (PublicKey pk')
      let clientCommand = Lib.Client.createUser userPrincipal
      result <- runClientM clientCommand $ mkClientEnv mgr url
      case result of
        Left err -> putStrLn $ "Error: " ++ show err
        Right _ -> do
          putStrLn $ "Created user " ++ unpack email
          putStrLn $ "Public key " ++ unpack pk


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl "http://localhost:8080"
