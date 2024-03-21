{-# LANGUAGE OverloadedStrings #-}
module Lib.Command.Create.User
  ( createUser
  , createUserOptions
  , CreateUser(..)
  ) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text as T
import Data.Text.Encoding
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client

import Lib.Client.Auth
import Lib.Client.Util
import Lib.Config
import Lib.IAM (UserId(..), User(..))
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
      let user = User (UserEmail email) [] [] [PublicKey pk']
      let clientCommand = Lib.Client.createUser user
      result <- runClientM clientCommand $ mkClientEnv mgr url
      case result of
        Left err -> handleClientError err
        Right _ -> return ()


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl =<< configURL


createUserOptions :: Parser CreateUser
createUserOptions = CreateUser
  <$> argument str
      ( metavar "EMAIL"
     <> help "Email for user"
      )
  <*> optional ( strOption
      ( long "public-key"
     <> metavar "PUBLIC_KEY"
     <> help "Public key for user"
      ) )
