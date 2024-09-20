module IAM.Server.Context
  ( Ctx(..)
  ) where

import Events.Client
import IAM.Client


data Ctx db = Ctx
  { ctxDB :: db
  , ctxIAMClient :: IAMClient
  , ctxEventsClient :: EventsClient
  }
