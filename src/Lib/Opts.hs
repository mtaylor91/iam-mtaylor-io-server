{-# LANGUAGE OverloadedStrings #-}
module Lib.Opts ( options, run, ServerOptions(..) ) where

import Data.ByteString (ByteString)
import Data.Text
import Data.Word (Word16)
import Options.Applicative

import Lib.GenerateKeypair
import Lib.IAM.DB.InMemory
import Lib.IAM.DB.Postgres
import Lib.Init
import Lib.Server


data Command
  = GenerateKeypair
  | Server !ServerOptions
  deriving (Show)


newtype Options = Options Command


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
  ( command "server"
    (info (Server <$> serverOptions) (progDesc "Start the server"))
  <> command "generate-keypair"
    (info (pure GenerateKeypair) (progDesc "Generate a keypair"))
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
    Options GenerateKeypair -> generateKeypair
    Options (Server opts') -> runServer opts'


runServer :: ServerOptions -> IO ()
runServer opts =
  if postgres opts
    then flip startApp (port opts) =<< initDB adminEmail' adminPublicKey' =<<
      connectToDatabase
      (postgresHost opts)
      (postgresPort opts)
      (postgresDatabase opts)
      (postgresUserName opts)
      (postgresPassword opts)
    else flip startApp (port opts) =<< initDB adminEmail' adminPublicKey' =<< inMemory
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
