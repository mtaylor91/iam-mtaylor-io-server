module IAM.Server.Session
  ( startSessionManager
  ) where

import Control.Concurrent
import Control.Monad.Except

import IAM.Server.Context
import IAM.Server.DB
import IAM.Session
import IAM.UserIdentifier


startSessionManager :: DB db => Ctx db -> UserIdentifier -> SessionId -> IO ()
startSessionManager ctx uid sid = do
  let db = ctxDB ctx
  _ <- forkIO $ sessionManager db uid sid
  return ()


sessionManager :: DB db => db -> UserIdentifier -> SessionId -> IO ()
sessionManager db uid sid = do
  result <- runExceptT $ refreshSession db uid sid
  case result of
    Left e -> print e
    Right _ -> return ()
  threadDelay minute
  sessionManager db uid sid
  where
  millisecond = 1000
  second = 1000 * millisecond
  minute = 60 * second
