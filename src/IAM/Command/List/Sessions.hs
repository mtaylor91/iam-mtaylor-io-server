module IAM.Command.List.Sessions
  ( listSessions
  , listSessionsOptions
  , ListSessionsOptions(..)
  ) where

import Data.Aeson (encode, toJSON)
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import IAM.Client.Auth
import IAM.Client.Util
import IAM.UserIdentifier (UserIdentifier(..), UserId(..))
import IAM.Session
import qualified IAM.Client


data ListSessionsOptions = ListSessionsOptions
  { listSessionsUser :: !(Maybe Text)
  , listSessionsOffset :: !(Maybe Int)
  , listSessionsLimit :: !(Maybe Int)
  } deriving (Show)


listSessions :: ListSessionsOptions -> IO ()
listSessions opts = case listSessionsUser opts of
  Nothing -> listCallerSessions opts
  Just user -> listUserSessions user opts


listCallerSessions :: ListSessionsOptions -> IO ()
listCallerSessions opts =
  let sessionsClient = IAM.Client.mkCallerSessionsClient
      listClient = IAM.Client.listSessions sessionsClient
   in runWithClient listClient opts


listUserSessions :: Text -> ListSessionsOptions -> IO ()
listUserSessions user opts = case readMaybe (unpack user) of
  Just uuid -> listUserSessionsByUUID uuid opts
  Nothing -> listUserSessionsByEmail user opts


listUserSessionsByUUID :: UUID -> ListSessionsOptions -> IO ()
listUserSessionsByUUID uuid = listUserSessionsByIdentifier userIdentifier
  where userIdentifier = UserId $ UserUUID uuid


listUserSessionsByEmail :: Text -> ListSessionsOptions -> IO ()
listUserSessionsByEmail email = listUserSessionsByIdentifier userIdentifier
  where userIdentifier = UserEmail email


listUserSessionsByIdentifier :: UserIdentifier -> ListSessionsOptions -> IO ()
listUserSessionsByIdentifier userIdentifier opts =
  let userClient = IAM.Client.mkUserClient userIdentifier
      sessionsClient = IAM.Client.userSessionsClient userClient
      listClient = IAM.Client.listSessions sessionsClient
   in runWithClient listClient opts


listSessionsOptions :: Parser ListSessionsOptions
listSessionsOptions = ListSessionsOptions
  <$> optional (argument str (metavar "USER"))
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


runWithClient ::
  (Maybe Int -> Maybe Int -> ClientM [Session]) -> ListSessionsOptions -> IO ()
runWithClient c opts = do
  let maybeOffset = listSessionsOffset opts
  let maybeLimit = listSessionsLimit opts
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  r <- runClientM (c maybeOffset maybeLimit) $ mkClientEnv mgr url
  case r of
    Right sessions ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON sessions)
    Left err ->
      handleClientError err
