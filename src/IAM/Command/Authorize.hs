module IAM.Command.Authorize
  ( authorize
  , authorizeCommand
  , AuthorizeCommand(..)
  ) where

import Data.Text
import Data.Text.Encoding
import Options.Applicative
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import Text.Read

import IAM.Authentication
import IAM.Authorization
import IAM.Client.Auth
import IAM.Client.Util
import IAM.UserIdentifier
import qualified IAM.Client


data AuthorizeCommand = AuthorizeCommand
  { authorizeUser :: !Text
  , authorizeHost :: !Text
  , authorizeMethod :: !Text
  , authorizeResource :: !Text
  } deriving (Show)


authorize :: AuthorizeCommand -> IO ()
authorize cmd = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  reqUser <- case readMaybe (unpack $ authorizeUser cmd) of
    Nothing -> return $ UserEmail $ authorizeUser cmd
    Just uuid -> return $ UserId $ UserUUID uuid

  let reqMethod = encodeUtf8 $ authorizeMethod cmd
  let reqAction = actionFromMethod reqMethod
  let req = AuthorizationRequest
        { authorizationRequestUser = reqUser
        , authorizationRequestAction = reqAction
        , authorizationRequestResource = authorizeResource cmd
        , authorizationRequestHost = authorizeHost cmd
        }

  let authorizeClient = IAM.Client.authorizeClient req
  r <- runClientM authorizeClient $ mkClientEnv mgr url
  case r of
    Right (AuthorizationResponse decision) ->
      print decision
    Left err ->
      handleClientError err


authorizeCommand :: Parser AuthorizeCommand
authorizeCommand = AuthorizeCommand
  <$> argument str
      ( metavar "USER"
     <> help "User to authorize"
      )
  <*> argument str
      ( metavar "HOST"
      <> help "Host to authorize"
      )
  <*> argument str
      ( metavar "METHOD"
     <> help "Method to authorize"
      )
  <*> argument str
      ( metavar "RESOURCE"
     <> help "Resource to authorize"
      )
