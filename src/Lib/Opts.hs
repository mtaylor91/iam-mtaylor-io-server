{-# LANGUAGE OverloadedStrings #-}
module Lib.Opts ( options, run, Options(..) ) where

import Options.Applicative

import Lib.InMemory
import Lib.Server


newtype Options = Options
  { port :: Int
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


runOptions :: Options -> IO ()
runOptions opts = do
  db <- inMemory
  putStrLn "Starting server..."
  startApp db (port opts)


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> progDesc "Start the server"
     <> header "api-mtaylor-io - API server for api.mtaylor.io service."
      )
