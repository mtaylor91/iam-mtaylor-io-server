{-# LANGUAGE OverloadedStrings #-}
module IAM.Command.Create.User
  ( createUser
  , createUserOptions
  , CreateUser(..)
  ) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Text as T
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import IAM.Client.Auth
import IAM.Client.Util
import IAM.Config
import IAM.IAM (GroupId(..), UserId(..), User(..))
import qualified IAM.Client


data CreateUser = CreateUser
  { createUserEmailOrUUID :: !Text
  , createUserPublicKey :: !(Maybe Text)
  , createUserGroups :: ![Text]
  } deriving (Show)


createUser :: CreateUser -> IO ()
createUser createUserInfo =
  case readMaybe (unpack $ createUserEmailOrUUID createUserInfo) of
    Just uuid -> createUserByUUID createUserInfo uuid
    Nothing -> createUserByEmail createUserInfo $ createUserEmailOrUUID createUserInfo


createUserByEmail :: CreateUser -> Text -> IO ()
createUserByEmail createUserInfo = createUserById createUserInfo . UserEmail


createUserByUUID :: CreateUser -> UUID -> IO ()
createUserByUUID createUserInfo = createUserById createUserInfo . UserUUID


createUserById :: CreateUser -> UserId -> IO ()
createUserById createUserInfo uid = do
  case createUserPublicKey createUserInfo of
    Just pk -> do
      createUserById' createUserInfo uid pk
    Nothing -> do
      (pk, sk) <- createKeypair
      createUserById' createUserInfo uid $ encodeBase64 (unPublicKey pk)
      case uid of
        UserEmail email -> printUserEmailShellVars email pk sk
        UserUUID uuid -> printUserUUIDShellVars uuid pk sk


createUserById' :: CreateUser -> UserId -> Text -> IO ()
createUserById' createUserInfo uid pk = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager $ tlsManagerSettings { managerModifyRequest = clientAuth auth }
  case decodeBase64 (encodeUtf8 pk) of
    Left _ ->
      putStrLn "Invalid public key: base64 decoding failed"
    Right pk' -> do
      let user = User uid (gid <$> createUserGroups createUserInfo) [] [PublicKey pk']
      let clientCommand = IAM.Client.createUser user
      result <- runClientM clientCommand $ mkClientEnv mgr url
      case result of
        Left err -> handleClientError err
        Right _ -> return ()
  where
    gid :: Text -> GroupId
    gid t = case readMaybe (unpack t) of
      Just uuid -> GroupUUID uuid
      Nothing -> GroupName t


createUserOptions :: Parser CreateUser
createUserOptions = CreateUser
  <$> argument str
      ( metavar "EMAIL | UUID"
     <> help "Email or UUID for user"
      )
  <*> optional ( strOption
      ( long "public-key"
     <> metavar "PUBLIC_KEY"
     <> help "Public key for user"
      ) )
  <*> some ( strOption
      ( long "group"
     <> metavar "GROUP"
     <> help "Group for user"
      ) )
