{-# LANGUAGE OverloadedStrings #-}
module IAM.Command.Server
  ( server
  , serverOptions
  , ServerOptions(..)
  ) where

import Data.ByteString (ByteString)
import Data.Text as T
import Data.Word (Word16)
import Options.Applicative

import IAM.Config
import IAM.Server.API
import IAM.Server.Init
import IAM.Server.IAM.DB.InMemory
import IAM.Server.IAM.DB.Postgres


data ServerOptions = ServerOptions
  { port :: !Int
  , postgres :: !Bool
  , postgresHost :: !ByteString
  , postgresPort :: !Word16
  , postgresDatabase :: !ByteString
  , postgresUserName :: !ByteString
  , postgresPassword :: !ByteString
  } deriving (Show)


server :: ServerOptions -> IO ()
server opts = do
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
