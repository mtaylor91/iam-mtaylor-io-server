module IAM.Command.List.Logins
  ( listLogins
  , listLoginsOptions
  , ListLoginsOptions(..)
  ) where

import Options.Applicative
import Data.Aeson (encode, toJSON)
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import IAM.Client
import IAM.Client.Auth
import IAM.Client.Util


data ListLoginsOptions = ListLoginsOptions
  { listLoginsOffset :: Maybe Int
  , listLoginsLimit :: Maybe Int
  } deriving (Show)


listLogins :: ListLoginsOptions -> IO ()
listLogins opts = do
  let offset = listLoginsOffset opts
  let limit = listLoginsLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let clientReq = listCallerLoginRequests offset limit
  result <- runClientM clientReq $ mkClientEnv mgr url
  case result of
    Left err ->
      handleClientError err
    Right response -> do
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON response)


listLoginsOptions :: Parser ListLoginsOptions
listLoginsOptions = ListLoginsOptions
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
