{-# LANGUAGE OverloadedStrings #-}
module IAM.Command.Create.User
  ( createUser
  , createUserOptions
  , CreateUser(..)
  ) where

import Crypto.Sign.Ed25519
import Data.ByteString.Base64
import Data.Maybe
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
import IAM.Types (GroupId(..), User(..), UserId(..), UserPublicKey(..))
import qualified IAM.Client


data CreateUser = CreateUser
  { createUserEmailOrUUID :: !Text
  , createUserDescription :: !(Maybe Text)
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
      let upk' = upk (PublicKey pk') (createUserDescription createUserInfo)
      let user = User uid (gid <$> createUserGroups createUserInfo) [] [upk']
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
    upk :: PublicKey -> Maybe Text -> UserPublicKey
    upk pk' = UserPublicKey pk' . fromMaybe "CLI"


createUserOptions :: Parser CreateUser
createUserOptions = CreateUser
  <$> argument str
      ( metavar "EMAIL | UUID"
     <> help "Email or UUID for user"
      )
  <*> optional ( argument str
      ( metavar "DESCRIPTION"
     <> help "Description for user's public key"
      ) )
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
