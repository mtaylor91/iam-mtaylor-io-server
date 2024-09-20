module IAM.Server.Context
  ( Ctx(..)
  ) where

import IAM.Client


data Ctx db = Ctx
  { ctxDB :: db
  , ctxIAMClient :: IAMClient
  }
