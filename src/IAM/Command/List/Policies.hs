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
  { listPoliciesSearch :: !(Maybe Text)
  , listPoliciesOffset :: !(Maybe Int)
  , listPoliciesLimit :: !(Maybe Int)
  } deriving (Show)


listPolicies :: ListPoliciesOptions -> IO ()
listPolicies opts = do
  let search = listPoliciesSearch opts
  let offset = listPoliciesOffset opts
  let limit = listPoliciesLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let clientOp = IAM.Client.listPolicies search offset limit
  result <- runClientM clientOp $ mkClientEnv mgr url
  case result of
    Right policies ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON policies)
    Left err ->
      handleClientError err


listPoliciesOptions :: Parser ListPoliciesOptions
listPoliciesOptions = ListPoliciesOptions
  <$> optional (strOption
    ( long "search"
    <> short 's'
    <> metavar "SEARCH"
    <> help "Search term for policies" ))
  <*> optional (option auto
    ( long "offset"
    <> short 'o'
    <> metavar "OFFSET"
    <> help "Offset for pagination" ))
  <*> optional (option auto
    ( long "limit"
    <> short 'l'
    <> metavar "LIMIT"
    <> help "Limit for pagination" ))
