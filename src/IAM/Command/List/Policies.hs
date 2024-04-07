module IAM.Command.List.Policies
  ( listPolicies
  , listPoliciesOptions
  , ListPoliciesOptions(..)
  ) where

import Data.Aeson (encode, toJSON)
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client

import IAM.Client.Auth
import IAM.Client.Util
import qualified IAM.Client


data ListPoliciesOptions = ListPoliciesOptions
  { listPoliciesOffset :: Maybe Int
  , listPoliciesLimit :: Maybe Int
  } deriving (Show)


listPolicies :: ListPoliciesOptions -> IO ()
listPolicies opts = do
  let offset = listPoliciesOffset opts
  let limit = listPoliciesLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  result <- runClientM (IAM.Client.listPolicies offset limit) $ mkClientEnv mgr url
  case result of
    Right policies ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON policies)
    Left err ->
      handleClientError err


listPoliciesOptions :: Parser ListPoliciesOptions
listPoliciesOptions = ListPoliciesOptions
  <$> optional (option auto
    ( long "offset"
    <> short 'o'
    <> metavar "OFFSET"
    <> help "Offset for pagination" ))
  <*> optional (option auto
    ( long "limit"
    <> short 'l'
    <> metavar "LIMIT"
    <> help "Limit for pagination" ))
