module IAM.Command.List.Users
  ( listUsers
  , listUsersOptions
  , ListUsersOptions(..)
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


data ListUsersOptions = ListUsersOptions
  { listUsersOffset :: !(Maybe Int)
  , listUsersLimit :: !(Maybe Int)
  } deriving (Show)


listUsers :: ListUsersOptions -> IO ()
listUsers opts = do
  let maybeOffset = listUsersOffset opts
  let maybeLimit = listUsersLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let clientOp = IAM.Client.listUsers Nothing maybeOffset maybeLimit
  r <- runClientM clientOp $ mkClientEnv mgr url
  case r of
    Right users ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON users)
    Left err ->
      handleClientError err


listUsersOptions :: Parser ListUsersOptions
listUsersOptions = ListUsersOptions
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
