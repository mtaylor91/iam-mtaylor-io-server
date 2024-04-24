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
import IAM.User (SortUsersBy, parseSortUsersBy)
import qualified IAM.Client


data ListUsersOptions = ListUsersOptions
  { listUsersSearch :: !(Maybe Text)
  , listUsersSort :: !(Maybe Text)
  , listUsersOffset :: !(Maybe Int)
  , listUsersLimit :: !(Maybe Int)
  } deriving (Show)


listUsers :: ListUsersOptions -> IO ()
listUsers opts =
  case listUsersSort opts of
    Nothing -> listUsers' opts Nothing
    Just sort ->
      case parseSortUsersBy sort of
        Nothing -> putStrLn "Invalid sort order"
        Just sort' -> listUsers' opts (Just sort')


listUsers' :: ListUsersOptions -> Maybe SortUsersBy -> IO ()
listUsers' opts maybeSort = do
  let maybeSearch = listUsersSearch opts
  let maybeOffset = listUsersOffset opts
  let maybeLimit = listUsersLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let clientOp = IAM.Client.listUsers maybeSearch maybeSort maybeOffset maybeLimit
  r <- runClientM clientOp $ mkClientEnv mgr url
  case r of
    Right users ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON users)
    Left err ->
      handleClientError err


listUsersOptions :: Parser ListUsersOptions
listUsersOptions = ListUsersOptions
  <$> optional (strOption
    ( long "search"
    <> short 's'
    <> metavar "SEARCH"
    <> help "Search string for filtering users" ))
  <*> optional (strOption
    ( long "sort"
    <> short 'r'
    <> metavar "SORT"
    <> help "Sort order for users" ))
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
