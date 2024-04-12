module IAM.Server.Context
  ( Ctx(..)
  ) where


newtype Ctx db = Ctx { ctxDB :: db }
