{-# LANGUAGE OverloadedStrings #-}
module IAM.Command ( options, run, ServerOptions(..) ) where

import Options.Applicative

import IAM.Command.Server


newtype Command = Server ServerOptions deriving (Show)


newtype Options = Options Command deriving (Show)


options :: Parser Options
options = Options <$> hsubparser
  ( command "server"
    (info (Server <$> serverOptions) (progDesc "Start the server"))
  )


runOptions :: Options -> IO ()
runOptions opts =
  case opts of
    Options (Server opts') ->
      server opts'


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> header "iam-mtaylor-io - API server for iam.mtaylor.io service."
      )
