module IAM.Command.Delete.Session
  ( deleteSession
  , deleteSessionOptions
  , DeleteSession(..)
  ) where

import Data.Text
import Data.Text.Encoding
import Options.Applicative
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import System.Exit
import Text.Email.Validate
import Text.Read (readMaybe)

import IAM.Client.Auth
import IAM.Client.Util
import IAM.Config
import IAM.Session
import IAM.UserIdentifier
import qualified IAM.Client as C


data DeleteSession = DeleteSession
  { deleteSessionUserId :: Text
  , deleteSessionSessionId :: Text
  } deriving (Eq, Show)


deleteSession :: DeleteSession -> IO ()
deleteSession (DeleteSession userIdentifier sessionIdentifier) =
  case (readMaybe $ unpack userIdentifier, readMaybe $ unpack sessionIdentifier) of
    (Just uuuid, Just suuid) ->
      let uid = UserIdentifier (Just $ UserUUID uuuid) Nothing Nothing
       in deleteSessionByUserIdentifier uid (SessionUUID suuid)
    (Nothing, Just sid) ->
      if isValid $ encodeUtf8 userIdentifier
      then do
        let uid = UserIdentifier Nothing Nothing (Just userIdentifier)
        deleteSessionByUserIdentifier uid (SessionUUID sid)
      else do
        let uid = UserIdentifier Nothing (Just userIdentifier) Nothing
        deleteSessionByUserIdentifier uid (SessionUUID sid)
    (_, Nothing) -> do
      putStrLn "Invalid session id."
      exitFailure


deleteSessionByUserIdentifier :: UserIdentifier -> SessionId -> IO ()
deleteSessionByUserIdentifier uid sid = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let userClient = C.mkUserClient uid
  let sessionsClient = C.userSessionsClient userClient
  let sessionClient' = C.sessionClient sessionsClient sid
  let deleteSession' = C.deleteSession sessionClient'
  r <- runClientM deleteSession' $ mkClientEnv mgr url
  case r of
    Left err -> handleClientError err
    Right _ -> do
      let prefix = "unset " ++ envPrefix ++ "_"
      putStrLn $ prefix ++ "SESSION_ID"
      putStrLn $ prefix ++ "SESSION_TOKEN"


deleteSessionOptions :: Parser DeleteSession
deleteSessionOptions = DeleteSession
  <$> argument str
      ( metavar "USER_ID"
     <> help "The email or uuid of the user to delete the session for."
      )
  <*> argument str
      ( metavar "SESSION_ID"
     <> help "The id of the session to delete."
      )
