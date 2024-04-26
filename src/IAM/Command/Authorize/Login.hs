module IAM.Command.Authorize.Login
  ( authorizeLogin
  , authorizeLoginCommand
  , AuthorizeLoginCommand(..)
  ) where

import Data.Text
import Data.UUID
import Options.Applicative
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import System.Exit

import IAM.Client
import IAM.Client.Auth
import IAM.Client.Util
import IAM.Login


newtype AuthorizeLoginCommand = AuthorizeLoginCommand
  { authorizeLoginId :: Text }
  deriving (Show)


authorizeLogin :: AuthorizeLoginCommand -> IO ()
authorizeLogin cmd = case fromText $ authorizeLoginId cmd of
  Just uuid -> authorizeLoginById $ LoginRequestId uuid
  Nothing -> do
    putStrLn "Invalid login ID"
    exitFailure


authorizeLoginById :: LoginRequestId -> IO ()
authorizeLoginById loginId = do
  let lrc = mkCallerLoginRequestClient loginId
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  res <- runClientM (grantLoginRequest lrc) $ mkClientEnv mgr url
  case res of
    Left err -> do
      putStrLn $ "Error: " ++ show err
      exitFailure
    Right _ -> do
      putStrLn "Login authorized"
      exitSuccess


authorizeLoginCommand :: Parser AuthorizeLoginCommand
authorizeLoginCommand = AuthorizeLoginCommand
  <$> argument str
    ( metavar "ID"
    <> help "ID of the login to authorize"
    )
