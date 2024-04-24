module IAM.Command.Delete.User
  ( deleteUser
  , deleteUserOptions
  , DeleteUser(..)
  ) where

import Data.Text
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import IAM.Client.Auth
import IAM.Client.Util
import IAM.UserIdentifier
import qualified IAM.Client


newtype DeleteUser = DeleteUser
  { deleteUserUserId :: Text
  } deriving (Show)


deleteUser :: DeleteUser -> IO ()
deleteUser deleteUserInfo =
  case readMaybe (unpack $ deleteUserUserId deleteUserInfo) of
    Just uuid -> deleteUserByUUID uuid
    Nothing -> deleteUserByEmail $ deleteUserUserId deleteUserInfo


deleteUserByEmail :: Text -> IO ()
deleteUserByEmail email = deleteUserById $ UserIdentifier Nothing Nothing (Just email)


deleteUserByUUID :: UUID -> IO ()
deleteUserByUUID uuid =
  deleteUserById $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing


deleteUserById :: UserIdentifier -> IO ()
deleteUserById uid = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  let userClient = IAM.Client.mkUserClient uid
  res <- runClientM (IAM.Client.deleteUser userClient) $ mkClientEnv mgr url
  case res of
    Left err -> handleClientError err
    Right _ -> return ()


deleteUserOptions :: Parser DeleteUser
deleteUserOptions = DeleteUser
  <$> argument str
      ( metavar "USER_ID"
     <> help "The email or uuid of the user to delete."
      )
