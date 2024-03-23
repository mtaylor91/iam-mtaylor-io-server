module Lib.Command.List.Policies
  ( listPolicies
  ) where

import Data.Aeson (encode, toJSON)
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import Lib.Client.Auth
import Lib.Client.Util
import qualified Lib.Client


listPolicies :: IO ()
listPolicies = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  result <- runClientM Lib.Client.listPolicies $ mkClientEnv mgr url
  case result of
    Right policies ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON policies)
    Left err ->
      handleClientError err
