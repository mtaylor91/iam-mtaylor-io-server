module Lib.Command.Get.User
  ( Lib.Command.Get.User.getUser
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text (Text, unpack)
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import Text.Read
import qualified Data.Text as T

import Lib.Client
import Lib.Client.Auth
import Lib.Client.Util
import Lib.IAM (UserId(..))


getUser :: Maybe Text -> IO ()
getUser = maybe getCurrentUser getSpecifiedUser


getSpecifiedUser :: Text -> IO ()
getSpecifiedUser uid =
  case readMaybe (unpack uid) of
    Just uuid -> getUserByUUID uuid
    Nothing -> getUserByEmail uid


getCurrentUser :: IO ()
getCurrentUser = do
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  url <- serverUrl
  result <- runClientM Lib.Client.getCaller $ mkClientEnv mgr url
  case result of
    Right user ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON user)
    Left err ->
      handleClientError err


getUserByUUID :: UUID -> IO ()
getUserByUUID = getUserById . UserUUID


getUserByEmail :: Text -> IO ()
getUserByEmail = getUserById . UserEmail


getUserById :: UserId -> IO ()
getUserById uid = do
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  url <- serverUrl
  let userClient = mkUserClient uid
  result <- runClientM (Lib.Client.getUser userClient) $ mkClientEnv mgr url
  case result of
    Right user ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON user)
    Left err ->
      handleClientError err
