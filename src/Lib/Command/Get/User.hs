module Lib.Command.Get.User
  ( Lib.Command.Get.User.getUser
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text (Text)
import Data.Text.Encoding
import Network.HTTP.Client
import Servant.Client
import qualified Data.Text as T

import Lib.Client
import Lib.Client.Auth
import Lib.IAM (UserId(..))


getUser :: Text -> IO ()
getUser email = do
  auth <- clientAuthInfo
  mgr <- newManager defaultManagerSettings { managerModifyRequest = clientAuth auth }
  url <- serverUrl
  let userClient = mkUserClient $ UserEmail email
  result <- runClientM (Lib.Client.getUser userClient) $ mkClientEnv mgr url
  case result of
    Right user ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON user)
    Left err ->
      putStrLn $ "Error: " ++ show err


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl "http://localhost:8080"
