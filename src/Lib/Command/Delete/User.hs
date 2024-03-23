module Lib.Command.Delete.User
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

import Lib.Client.Auth
import Lib.Client.Util
import Lib.IAM
import qualified Lib.Client


newtype DeleteUser = DeleteUser
  { deleteUserUserId :: Text
  } deriving (Show)


deleteUser :: DeleteUser -> IO ()
deleteUser deleteUserInfo =
  case readMaybe (unpack $ deleteUserUserId deleteUserInfo) of
    Just uuid -> deleteUserByUUID uuid
    Nothing -> deleteUserByEmail $ deleteUserUserId deleteUserInfo


deleteUserByEmail :: Text -> IO ()
deleteUserByEmail = deleteUserById . UserEmail


deleteUserByUUID :: UUID -> IO ()
deleteUserByUUID = deleteUserById . UserUUID


deleteUserById :: UserId -> IO ()
deleteUserById uid = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  let userClient = Lib.Client.mkUserClient uid
  res <- runClientM (Lib.Client.deleteUser userClient) $ mkClientEnv mgr url
  case res of
    Left err -> handleClientError err
    Right _ -> return ()


deleteUserOptions :: Parser DeleteUser
deleteUserOptions = DeleteUser
  <$> argument str
      ( metavar "USER_ID"
     <> help "The email or uuid of the user to delete."
      )
