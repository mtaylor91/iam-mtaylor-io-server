{-# LANGUAGE OverloadedStrings #-}
module Lib.Opts ( options, run, ServerOptions(..) ) where

import Data.ByteString (ByteString)
import Data.Text
import Data.Word (Word16)
import Options.Applicative

import Lib.Command.Keypair
import Lib.Command.Create.User
import Lib.Server.API
import Lib.Server.Init
import Lib.Server.IAM.DB.InMemory
import Lib.Server.IAM.DB.Postgres


data Command
  = Create !CreateCommand
  | Keypair !KeypairOptions
  | Server !ServerOptions
  deriving (Show)


newtype Options = Options Command deriving (Show)


newtype CreateCommand
  = User UserCreateOptions
  deriving (Show)


data UserCreateOptions = UserCreateOptions
  { email :: !Text
  , publicKey :: !(Maybe Text)
  } deriving (Show)


newtype KeypairOptions = KeypairOptions Text deriving (Show)


data ServerOptions = ServerOptions
  { adminEmail :: !Text
  , adminPublicKey :: !Text
  , port :: !Int
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
    (info (Create <$> createCommand) (progDesc "Create a user"))
  <> command "keypair"
    (info (Keypair <$> keypairOptions) (progDesc "Generate a keypair"))
  <> command "server"
    (info (Server <$> serverOptions) (progDesc "Start the server"))
  )


createCommand :: Parser CreateCommand
createCommand = subparser
  ( command "user"
    (info (User <$> userCreateOptions) (progDesc "Create a user"))
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
  <$> strOption
      ( long "email"
     <> metavar "EMAIL"
     <> help "Email for keypair"
      )


serverOptions :: Parser ServerOptions
serverOptions = ServerOptions
  <$> strOption
      ( long "admin-email"
     <> metavar "EMAIL"
     <> help "Admin email"
      )
  <*> strOption
      ( long "admin-public-key"
     <> metavar "PUBLIC_KEY"
     <> help "Admin public key"
      )
  <*> option auto
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
    Options (Create (User (UserCreateOptions email' publicKey'))) ->
      createUser email' publicKey'
    Options (Keypair (KeypairOptions email')) ->
      generateKeypair email'
    Options (Server opts') ->
      runServer opts'


runServer :: ServerOptions -> IO ()
runServer opts =
  if postgres opts
    then startApp (port opts) =<< initDB adminEmail' adminPublicKey' =<<
      connectToDatabase
      (postgresHost opts)
      (postgresPort opts)
      (postgresDatabase opts)
      (postgresUserName opts)
      (postgresPassword opts)
    else startApp (port opts) =<< initDB adminEmail' adminPublicKey' =<< inMemory
  where
    adminEmail' = adminEmail opts
    adminPublicKey' = adminPublicKey opts


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> header "api-mtaylor-io - API server for api.mtaylor.io service."
      )
