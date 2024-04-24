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
import IAM.Sort
import qualified IAM.Client


data ListUsersOptions = ListUsersOptions
  { listUsersSearch :: !(Maybe Text)
  , listUsersSort :: !(Maybe Text)
  , listUsersOrder :: !(Maybe Text)
  , listUsersOffset :: !(Maybe Int)
  , listUsersLimit :: !(Maybe Int)
  } deriving (Show)


listUsers :: ListUsersOptions -> IO ()
listUsers opts = do
  let maybeSort = listUsersSort opts >>= parseSortUsersBy
  let maybeOrder = listUsersOrder opts >>= parseSortOrder
  case (maybeSort, listUsersSort opts, maybeOrder, listUsersOrder opts) of
    (Nothing, Just sort, _, _) -> do
      putStrLn $ "Invalid sort: " ++ T.unpack sort
      return ()
    (_, _, Nothing, Just order) -> do
      putStrLn $ "Invalid order: " ++ T.unpack order
      return ()
    _ -> listUsers' opts maybeSort maybeOrder


listUsers' :: ListUsersOptions -> Maybe SortUsersBy -> Maybe SortOrder -> IO ()
listUsers' opts maybeSort maybeOrder = do
  let mSearch = listUsersSearch opts
  let mOffset = listUsersOffset opts
  let mLimit = listUsersLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let clientOp = IAM.Client.listUsers mSearch maybeSort maybeOrder mOffset mLimit
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
  <*> optional (strOption
    ( long "order"
    <> short 'd'
    <> metavar "ORDER"
    <> help "Order for sorting users" ))
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
