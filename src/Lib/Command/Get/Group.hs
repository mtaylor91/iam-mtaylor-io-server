module Lib.Command.Get.Group
  ( Lib.Command.Get.Group.getGroup
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import Text.Read

import Lib.Client
import Lib.Client.Auth
import Lib.Client.Util
import Lib.Config
import Lib.IAM


getGroup :: Text -> IO ()
getGroup nameOrId =
  case readMaybe (unpack nameOrId) of
    Just uuid ->
      getGroupByUUID uuid
    Nothing ->
      getGroupByName nameOrId


getGroupByUUID :: UUID -> IO ()
getGroupByUUID = getGroupById . GroupUUID


getGroupByName :: Text -> IO ()
getGroupByName = getGroupById . GroupName


getGroupById :: GroupId -> IO ()
getGroupById gid = do
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  url <- serverUrl
  let groupClient = mkGroupClient gid
  result <- runClientM (Lib.Client.getGroup groupClient) $ mkClientEnv mgr url
  case result of
    Right group' ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON group')
    Left err ->
      handleClientError err


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl =<< configURL
