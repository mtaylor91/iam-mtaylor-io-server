{-# LANGUAGE OverloadedStrings #-}
module Lib.Command.Create.User
  ( createUser
  , CreateUser(..)
  ) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text
import Data.Text.Encoding
import qualified Lib.Client
import Lib.Client.Auth
import Lib.IAM (UserId(..), UserPrincipal(..))
import Network.HTTP.Client
import Servant.Client


data CreateUser = CreateUser
  { createUserEmail :: !Text
  , createUserPublicKey :: !(Maybe Text)
  } deriving (Show)


createUser :: CreateUser -> IO ()
createUser createUserInfo = do
  url <- serverUrl
  case createUserPublicKey createUserInfo of
    Just pk -> do
      createUser' url (createUserEmail createUserInfo) pk
    Nothing -> do
      (pk, sk) <- createKeypair
      createUser' url (createUserEmail createUserInfo) $ encodeBase64 (unPublicKey pk)
      putStrLn $ "Public key: " ++ unpack (encodeBase64 (unPublicKey pk))
      putStrLn $ "Secret key: " ++ unpack (encodeBase64 (unSecretKey sk))


createUser' :: BaseUrl -> Text -> Text -> IO ()
createUser' url email pk = do
  auth <- clientAuthInfo
  mgr <- newManager $ defaultManagerSettings { managerModifyRequest = clientAuth auth }
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


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl "http://localhost:8080"
