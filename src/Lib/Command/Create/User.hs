{-# LANGUAGE OverloadedStrings #-}
module Lib.Command.Create.User
  ( createUser
  , CreateUser(..)
  ) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text as T
import Data.Text.Encoding
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import Lib.Client.Auth
import Lib.Config
import Lib.IAM (UserId(..), UserPrincipal(..))
import qualified Lib.Client


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
      printUserShellVars (createUserEmail createUserInfo) pk sk


createUser' :: BaseUrl -> Text -> Text -> IO ()
createUser' url email pk = do
  auth <- clientAuthInfo
  mgr <- newManager $ tlsManagerSettings { managerModifyRequest = clientAuth auth }
  case decodeBase64 (encodeUtf8 pk) of
    Left _ ->
      putStrLn "Invalid public key: base64 decoding failed"
    Right pk' -> do
      let userPrincipal = UserPrincipal (UserEmail email) (PublicKey pk')
      let clientCommand = Lib.Client.createUser userPrincipal
      result <- runClientM clientCommand $ mkClientEnv mgr url
      case result of
        Left err -> putStrLn $ "Error: " ++ show err
        Right _ -> return ()


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl =<< configURL
