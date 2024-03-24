{-# LANGUAGE OverloadedStrings #-}
module IAM.Command ( options, run, ServerOptions(..) ) where

import Options.Applicative

import IAM.Command.Create
import IAM.Command.Delete
import IAM.Command.Get
import IAM.Command.List
import IAM.Command.Keypair
import IAM.Command.Server


data Command
  = Create !CreateCommand
  | Delete !DeleteCommand
  | Get !GetCommand
  | List !ListCommand
  | Keypair !KeypairOptions
  | Server !ServerOptions
  deriving (Show)


newtype Options = Options Command deriving (Show)


options :: Parser Options
options = Options <$> hsubparser
  ( command "create"
    (info (Create <$> createCommand) (progDesc "Create resources"))
  <> command "delete"
    (info (Delete <$> deleteCommand) (progDesc "Delete resources"))
  <> command "get"
    (info (Get <$> getCommand) (progDesc "Get resources"))
  <> command "list"
    (info (List <$> listCommand) (progDesc "List resources"))
  <> command "keypair"
    (info (Keypair <$> keypairOptions) (progDesc "Generate a keypair"))
  <> command "server"
    (info (Server <$> serverOptions) (progDesc "Start the server"))
  )


runOptions :: Options -> IO ()
runOptions opts =
  case opts of
    Options (Create cmd) ->
      create cmd
    Options (Delete cmd) ->
      delete cmd
    Options (Get cmd) ->
      get cmd
    Options (List cmd) ->
      list cmd
    Options (Keypair opts') ->
      keypair opts'
    Options (Server opts') ->
      server opts'


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> header "api-mtaylor-io - API server for api.mtaylor.io service."
      )
