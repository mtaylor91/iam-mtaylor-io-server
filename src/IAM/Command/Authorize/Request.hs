module IAM.Command.Authorize.Request
  ( authorizeRequest
  , authorizeRequestCommand
  , AuthorizeRequestCommand(..)
  ) where

import Data.Text
import Data.Text.Encoding
import Options.Applicative
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client
import Text.Email.Validate
import Text.Read

import IAM.Authentication
import IAM.Authorization
import IAM.Client.Auth
import IAM.Client.Util
import IAM.UserIdentifier
import qualified IAM.Client


data AuthorizeRequestCommand = AuthorizeRequestCommand
  { authorizeUser :: !Text
  , authorizeHost :: !Text
  , authorizeMethod :: !Text
  , authorizeResource :: !Text
  } deriving (Show)


authorizeRequest :: AuthorizeRequestCommand -> IO ()
authorizeRequest cmd = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  reqUser <- case readMaybe (unpack $ authorizeUser cmd) of
    Just uuid ->
      return $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing
    Nothing ->
      if isValid $ encodeUtf8 $ authorizeUser cmd
      then return $ UserIdentifier Nothing Nothing (Just $ authorizeUser cmd)
      else return $ UserIdentifier Nothing (Just $ authorizeUser cmd) Nothing

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


authorizeRequestCommand :: Parser AuthorizeRequestCommand
authorizeRequestCommand = AuthorizeRequestCommand
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
