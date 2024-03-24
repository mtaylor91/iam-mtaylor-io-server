module IAM.Command.List.Users
  ( listUsers
  ) where

import Data.Aeson (encode, toJSON)
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import IAM.Client.Auth
import IAM.Client.Util
import qualified IAM.Client


listUsers :: IO ()
listUsers = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  result <- runClientM IAM.Client.listUsers $ mkClientEnv mgr url
  case result of
    Right users ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON users)
    Left err ->
      handleClientError err
