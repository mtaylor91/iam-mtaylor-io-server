{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Audit
  ( auditLoginSuccess
  ) where

import Data.Aeson
import Data.Aeson.KeyMap as KM
import Data.UUID
import Data.UUID.V4

import Events.Client
import Events.Client.API
import IAM.Server.Context
import IAM.UserIdentifier


auditLogUUID :: UUID
auditLogUUID =
  case fromText "f2d7835b-29f1-4f29-b3dd-04ce1d1ef939" of
    Nothing -> error "Invalid UUID"
    Just uuid -> uuid


auditLoginSuccess :: Ctx db -> UserId -> IO ()
auditLoginSuccess ctx (UserUUID userId) = do
  eventId <- nextRandom
  let eventsClient = ctxEventsClient ctx
  let auditTopicClient = topicClient auditLogUUID
  let auditEventClient = topicEventClient auditTopicClient eventId
  let updateEventClient = updateTopicEventClient auditEventClient
  let eventData = fromList
        [ ("userId", String $ toText userId)
        , ("event", String "login-success")
        ]
  result <- runEventsClient eventsClient $ updateEventClient eventData
  case result of
    Left e -> error $ "Error auditing login success: " ++ show e
    Right _ -> return ()
