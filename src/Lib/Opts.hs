{-# LANGUAGE OverloadedStrings #-}
module Lib.Opts ( options, run, Options(..) ) where

import Data.ByteString (ByteString)
import Data.Word (Word16)
import Options.Applicative

import Lib.IAM.DB.InMemory
import Lib.IAM.DB.Postgres
import Lib.Server


data Options = Options
  { port :: !Int
  , postgres :: !Bool
  , postgresHost :: !ByteString
  , postgresPort :: !Word16
  , postgresDatabase :: !ByteString
  , postgresUserName :: !ByteString
  , postgresPassword :: !ByteString
  } deriving (Show)


options :: Parser Options
options = Options
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
  if postgres opts
    then flip startApp (port opts) =<< connectToDatabase
      (postgresHost opts)
      (postgresPort opts)
      (postgresDatabase opts)
      (postgresUserName opts)
      (postgresPassword opts)
    else flip startApp (port opts) =<< inMemory


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> progDesc "Start the server"
     <> header "api-mtaylor-io - API server for api.mtaylor.io service."
      )
