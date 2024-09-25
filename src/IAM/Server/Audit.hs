{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Audit
  ( auditLoginSuccess
  , auditSessionCreated
  , auditSessionRefreshed
  ) where

import Data.Aeson
import Data.Aeson.KeyMap as KM
import Data.Text
import Data.UUID

import Events.Client
import Events.Client.API
import IAM.Server.Context
import IAM.Session
import IAM.UserIdentifier


auditLogUUID :: UUID
auditLogUUID =
  case fromText "f2d7835b-29f1-4f29-b3dd-04ce1d1ef939" of
    Nothing -> error "Invalid UUID"
    Just uuid -> uuid


auditLoginSuccess :: Ctx db -> UserId -> IO ()
auditLoginSuccess = auditUser "login-success"


auditSessionCreated :: Ctx db -> UserId -> SessionId -> IO ()
auditSessionCreated = auditSession "session-created"


auditSessionRefreshed :: Ctx db -> UserId -> SessionId -> IO ()
auditSessionRefreshed = auditSession "session-refreshed"


auditSession :: Text -> Ctx db -> UserId -> SessionId -> IO ()
auditSession evt ctx (UserUUID uid) (SessionUUID sid) = do
  let eventsClient = ctxEventsClient ctx
  let auditTopicClient = topicClient auditLogUUID
  let createEventClient = createTopicEventClient auditTopicClient
  let eventData = fromList
        [ ("event", String evt)
        , ("userId", String $ toText uid)
        , ("sessionId", String $ toText sid)
        ]
  result <- runEventsClient eventsClient $ createEventClient eventData
  case result of
    Left e -> error $ "Error auditing session creation: " ++ show e
    Right _ -> return ()


auditUser :: Text -> Ctx db -> UserId -> IO ()
auditUser evt ctx (UserUUID uid) = do
  let eventsClient = ctxEventsClient ctx
  let auditTopicClient = topicClient auditLogUUID
  let createEventClient = createTopicEventClient auditTopicClient
  let eventData = fromList
        [ ("event", String evt)
        , ("userId", String $ toText uid)
        ]
  result <- runEventsClient eventsClient $ createEventClient eventData
  case result of
    Left e -> error $ "Error auditing login success: " ++ show e
    Right _ -> return ()
