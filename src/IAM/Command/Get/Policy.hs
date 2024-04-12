module IAM.Command.Get.Policy
  ( IAM.Command.Get.Policy.getPolicy
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import Text.Read
import qualified Data.Text as T

import IAM.Client
import IAM.Client.Auth
import IAM.Client.Util
import IAM.Policy


getPolicy :: T.Text -> IO ()
getPolicy identifier = case readMaybe (T.unpack identifier) of
  Just uuid -> getPolicyByUUID uuid
  Nothing -> getPolicyByName identifier


getPolicyByUUID :: UUID -> IO ()
getPolicyByUUID uuid = getPolicyByIdentifier $ PolicyId $ PolicyUUID uuid


getPolicyByName :: T.Text -> IO ()
getPolicyByName = getPolicyByIdentifier . PolicyName


getPolicyByIdentifier :: PolicyIdentifier -> IO ()
getPolicyByIdentifier identifier = do
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  url <- serverUrl
  let policyClient = mkPolicyClient identifier
  result <- runClientM (IAM.Client.getPolicy policyClient) $ mkClientEnv mgr url
  case result of
    Right policy' ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON policy')
    Left err ->
      handleClientError err
