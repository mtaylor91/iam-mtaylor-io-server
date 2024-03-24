{-# LANGUAGE OverloadedStrings #-}
module IAM.Command.Server
  ( server
  , serverOptions
  , ServerOptions(..)
  ) where

import Control.Exception
import Data.ByteString (ByteString)
import Data.Text as T
import Data.Text.Encoding
import Options.Applicative
import System.Environment
import Text.Read

import IAM.Config
import IAM.Server.API
import IAM.Server.Init
import IAM.Server.IAM.DB.InMemory
import IAM.Server.IAM.DB.Postgres


data ServerOptions = ServerOptions
  { port :: !Int
  , postgres :: !Bool
  } deriving (Show)


server :: ServerOptions -> IO ()
server opts = do
  adminEmail <- T.pack <$> configEmail
  adminPublicKey <- T.pack <$> configPublicKey
  if postgres opts
    then startApp (port opts) =<< initDB adminEmail adminPublicKey =<< pgDB
    else startApp (port opts) =<< initDB adminEmail adminPublicKey =<< inMemory
  where
    pgDB = do
      pgHost <- loadEnvConfig "POSTGRES_HOST"
      pgPort <- readEnvConfig "POSTGRES_PORT"
      pgDatabase <- loadEnvConfig "POSTGRES_DATABASE"
      pgUserName <- loadEnvConfig "POSTGRES_USER"
      pgPassword <- loadEnvConfig "POSTGRES_PASSWORD"
      connectToDatabase pgHost pgPort pgDatabase pgUserName pgPassword


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


loadEnvConfig :: String -> IO ByteString
loadEnvConfig key = do
  maybeValue <- lookupEnv key
  case maybeValue of
    Nothing -> throw $ userError $ key ++ " environment variable not set"
    Just val -> return $ encodeUtf8 $ T.pack val


readEnvConfig :: Read t => String -> IO t
readEnvConfig key = do
  maybeValue <- lookupEnv key
  case maybeValue of
    Nothing -> throw $ userError $ key ++ " environment variable not set"
    Just val -> case readMaybe val of
      Nothing -> throw $ userError $ key ++ " environment variable not a valid value"
      Just val' -> return val'
