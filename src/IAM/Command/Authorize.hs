module IAM.Command.Authorize
  ( authorize
  , authorizeCommand
  , AuthorizeCommand(..)
  ) where

import Options.Applicative

import IAM.Command.Authorize.Login
import IAM.Command.Authorize.Request


data AuthorizeCommand
  = AuthorizeLogin !AuthorizeLoginCommand
  | AuthorizeRequest !AuthorizeRequestCommand
  deriving (Show)


authorize :: AuthorizeCommand -> IO ()
authorize (AuthorizeLogin cmd) = authorizeLogin cmd
authorize (AuthorizeRequest cmd) = authorizeRequest cmd


authorizeCommand :: Parser AuthorizeCommand
authorizeCommand = subparser
  ( command "login"
    (info (AuthorizeLogin <$> authorizeLoginCommand) (progDesc "Authorize login"))
  <> command "request"
    (info (AuthorizeRequest <$> authorizeRequestCommand) (progDesc "Authorize request"))
  )
