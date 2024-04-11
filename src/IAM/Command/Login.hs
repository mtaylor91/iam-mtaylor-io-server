module IAM.Command.Login
  ( login
  , loginOptions
  , LoginOptions(..)
  ) where

import Data.Text (unpack)
import Data.UUID (toText)
import Options.Applicative
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import IAM.Client
import IAM.Client.Auth
import IAM.Client.Util
import IAM.Config
import IAM.Session


data LoginOptions = LoginOptions deriving (Eq, Show)


login :: LoginOptions -> IO ()
login LoginOptions = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  let sessionsClient = mkCallerSessionsClient
  let createSession' = IAM.Client.createSession sessionsClient
  r <- runClientM createSession' $ mkClientEnv mgr url
  case r of
    Right session ->
      let sid = toText $ unSessionId $ createSessionId session
          token = createSessionToken session
          prefix = "export " ++ envPrefix ++ "_"
       in do
        putStrLn $ prefix ++ "SESSION_ID=\"" ++ unpack sid ++ "\""
        putStrLn $ prefix ++ "SESSION_TOKEN=\"" ++ unpack token ++ "\""
    Left err ->
      handleClientError err



loginOptions :: Parser LoginOptions
loginOptions = pure LoginOptions
