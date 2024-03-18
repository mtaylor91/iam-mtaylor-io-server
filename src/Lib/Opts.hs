{-# LANGUAGE OverloadedStrings #-}
module Lib.Opts ( options, run, ServerOptions(..) ) where

import Data.ByteString (ByteString)
import Data.Text as T
import Data.Word (Word16)
import Options.Applicative

import Lib.Command.Keypair
import Lib.Command.Create.User
import Lib.Command.Get.User
import Lib.Config
import Lib.Server.API
import Lib.Server.Init
import Lib.Server.IAM.DB.InMemory
import Lib.Server.IAM.DB.Postgres


data Command
  = Create !CreateCommand
  | Get !GetCommand
  | Keypair !KeypairOptions
  | Server !ServerOptions
  deriving (Show)


newtype Options = Options Command deriving (Show)


newtype CreateCommand
  = UserCreate UserCreateOptions
  deriving (Show)


data UserCreateOptions = UserCreateOptions
  { email :: !Text
  , publicKey :: !(Maybe Text)
  } deriving (Show)


newtype GetCommand
  = UserGet Text
  deriving (Show)


data KeypairOptions = KeypairOptions
  { keypairEmail :: !Text
  , keypairShell :: !Bool
  } deriving (Show)


data ServerOptions = ServerOptions
  { port :: !Int
  , postgres :: !Bool
  , postgresHost :: !ByteString
  , postgresPort :: !Word16
  , postgresDatabase :: !ByteString
  , postgresUserName :: !ByteString
  , postgresPassword :: !ByteString
  } deriving (Show)


options :: Parser Options
options = Options <$> hsubparser
  ( command "create"
    (info (Create <$> createCommand) (progDesc "Create resources"))
  <> command "get"
    (info (Get <$> getCommand) (progDesc "Get resources"))
  <> command "keypair"
    (info (Keypair <$> keypairOptions) (progDesc "Generate a keypair"))
  <> command "server"
    (info (Server <$> serverOptions) (progDesc "Start the server"))
  )


createCommand :: Parser CreateCommand
createCommand = subparser
  ( command "user"
    (info (UserCreate <$> userCreateOptions) (progDesc "Create a user"))
  )


getCommand :: Parser GetCommand
getCommand = subparser
  ( command "user"
    (info (UserGet <$> argument str (metavar "EMAIL")) (progDesc "Get a user"))
  )


userCreateOptions :: Parser UserCreateOptions
userCreateOptions = UserCreateOptions
  <$> argument str
      ( metavar "EMAIL"
     <> help "Email for user"
      )
  <*> optional ( strOption
      ( long "public-key"
     <> metavar "PUBLIC_KEY"
     <> help "Public key for user"
      ) )


keypairOptions :: Parser KeypairOptions
keypairOptions = KeypairOptions
  <$> argument str
      ( metavar "EMAIL"
     <> help "Email for keypair"
      )
  <*> switch
      ( long "shell"
     <> short 's'
     <> help "Format output for shell"
      )


serverOptions :: Parser ServerOptions
serverOptions = ServerOptions
  <$> option auto
      ( long "port"
     <> short 'p'
     <> metavar "PORT"
     <> help "Port to listen on"
     <> value 8080
     <> showDefault
      )
  <*> switch ( long "postgres"
      <> help "Use Postgres database"
      )
  <*> strOption ( long "postgres-host"
     <> metavar "HOST"
     <> help "Postgres host"
     <> value "localhost"
     <> showDefault
      )
  <*> option auto
      ( long "postgres-port"
      <> metavar "PORT"
      <> help "Postgres port"
      <> value 5432
      <> showDefault
      )
  <*> strOption ( long "postgres-database"
      <> metavar "DATABASE"
      <> help "Postgres database"
      <> value "iam"
      <> showDefault
      )
  <*> strOption ( long "postgres-username"
      <> metavar "USERNAME"
      <> help "Postgres username"
      <> value "iam"
      <> showDefault
      )
  <*> strOption ( long "postgres-password"
      <> metavar "PASSWORD"
      <> help "Postgres password"
      <> value "iam"
      <> showDefault
      )


runOptions :: Options -> IO ()
runOptions opts =
  case opts of
    Options (Create (UserCreate (UserCreateOptions email' publicKey'))) ->
      createUser $ CreateUser email' publicKey'
    Options (Get (UserGet email')) ->
      getUser email'
    Options (Keypair (KeypairOptions email' formatShell)) ->
      generateKeypair email' formatShell
    Options (Server opts') ->
      runServer opts'


runServer :: ServerOptions -> IO ()
runServer opts = do
  adminEmail <- T.pack <$> configEmail
  adminPublicKey <- T.pack <$> configPublicKey
  if postgres opts
    then startApp (port opts) =<< initDB adminEmail adminPublicKey =<<
      connectToDatabase
      (postgresHost opts)
      (postgresPort opts)
      (postgresDatabase opts)
      (postgresUserName opts)
      (postgresPassword opts)
    else startApp (port opts) =<< initDB adminEmail adminPublicKey =<< inMemory


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> header "api-mtaylor-io - API server for api.mtaylor.io service."
      )
