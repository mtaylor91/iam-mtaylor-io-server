module Lib.Command.Get.Policy
  ( Lib.Command.Get.Policy.getPolicy
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import qualified Data.Text as T

import Lib.Client
import Lib.Client.Auth
import Lib.Client.Util


getPolicy :: T.Text -> IO ()
getPolicy = getPolicyById . read . T.unpack


getPolicyById :: UUID -> IO ()
getPolicyById uuid = do
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  url <- serverUrl
  let policyClient = mkPolicyClient uuid
  result <- runClientM (Lib.Client.getPolicy policyClient) $ mkClientEnv mgr url
  case result of
    Right policy' ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON policy')
    Left err ->
      handleClientError err
