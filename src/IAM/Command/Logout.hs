module IAM.Command.Logout
  ( logout
  , logoutOptions
  , LogoutOptions(..)
  ) where

import Options.Applicative
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import IAM.Client
import IAM.Client.Auth
import IAM.Client.Util
import IAM.Config


data LogoutOptions = LogoutOptions deriving (Eq, Show)


logout :: LogoutOptions -> IO ()
logout LogoutOptions = do
  url <- serverUrl
  sid <- configSessionId
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let sessionsClient = mkCallerSessionsClient
  let sessionClient' = sessionClient sessionsClient sid
  let deleteSession' = deleteSession sessionClient'
  r <- runClientM deleteSession' $ mkClientEnv mgr url
  case r of
    Left err -> handleClientError err
    Right _ -> do
      let prefix = "unset " ++ envPrefix ++ "_"
      putStrLn $ prefix ++ "SESSION_ID"
      putStrLn $ prefix ++ "SESSION_TOKEN"


logoutOptions :: Parser LogoutOptions
logoutOptions = pure LogoutOptions
